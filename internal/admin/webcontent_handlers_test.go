package admin

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/webcontent"
)

func TestWebContentUploadRequiresAdministratorAndCSRFAndCanRollback(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "admin.json")
	if err := auth.SaveCredential(credentialPath, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	server := New(credential, nil)
	root := filepath.Join(t.TempDir(), "site")
	defaults := t.TempDir()
	if err := os.WriteFile(filepath.Join(defaults, "index.html"), []byte("default site"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := webcontent.Initialize(root, defaults); err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigureWebContent(root); err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	archive := webContentTestZip(t, "custom homepage")
	unauthorized := uploadRequest(t, handler, nil, "invalid", archive)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous upload status = %d", unauthorized.Code)
	}
	cookie := loginTestAdmin(t, server)
	badCSRF := uploadRequest(t, handler, cookie, "invalid", archive)
	if badCSRF.Code != http.StatusForbidden {
		t.Fatalf("bad-CSRF upload status = %d", badCSRF.Code)
	}
	csrf, _, ok := server.sessions.State(cookie.Value)
	if !ok {
		t.Fatal("administrator session expired during test")
	}
	response := uploadRequest(t, handler, cookie, csrf, archive)
	if response.Code != http.StatusOK {
		t.Fatalf("valid web content upload status = %d: %s", response.Code, response.Body.String())
	}
	var uploaded webcontent.Status
	if err := jsonUnmarshal(response.Body.Bytes(), &uploaded); err != nil {
		t.Fatal(err)
	}
	if uploaded.Current == "default" || uploaded.Previous != "default" {
		t.Fatalf("upload state = %+v", uploaded)
	}
	if contents, err := os.ReadFile(filepath.Join(root, "revisions", uploaded.Current, "index.html")); err != nil || string(contents) != "custom homepage" {
		t.Fatalf("published homepage = %q, %v", contents, err)
	}
	rollback := requestWithHeaders(handler, http.MethodPost, "/web-content/rollback", nil, cookie, map[string]string{"X-CSRF-Token": csrf})
	if rollback.Code != http.StatusOK {
		t.Fatalf("web content rollback status = %d: %s", rollback.Code, rollback.Body.String())
	}
	var restored webcontent.Status
	if err := jsonUnmarshal(rollback.Body.Bytes(), &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Current != "default" {
		t.Fatalf("rollback did not restore default revision: %+v", restored)
	}
}

func TestConfigureWebContentMigratesLegacyErrorPages(t *testing.T) {
	root := filepath.Join(t.TempDir(), "site")
	defaults := t.TempDir()
	if err := os.WriteFile(filepath.Join(defaults, "index.html"), []byte("existing homepage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := webcontent.Initialize(root, defaults); err != nil {
		t.Fatal(err)
	}
	status, err := webcontent.GetStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	oldRevision := filepath.Join(root, "revisions", status.Current)
	if err := os.WriteFile(filepath.Join(oldRevision, "errors", "403.html"), []byte("custom denial"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(oldRevision, "errors", "404.html")); err != nil {
		t.Fatal(err)
	}

	server := New(nil, nil)
	if err := server.ConfigureWebContent(root); err != nil {
		t.Fatal(err)
	}
	updated, err := webcontent.GetStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Current == status.Current || updated.Previous != status.Current {
		t.Fatalf("admin startup did not publish a migrated revision: before %+v, after %+v", status, updated)
	}
	assertWebContentFile(t, root, updated.Current, "index.html", "existing homepage")
	assertWebContentFile(t, root, updated.Current, "errors/403.html", "custom denial")
	assertWebContentFile(t, root, updated.Current, "errors/404.html", "Not found")
}

func assertWebContentFile(t *testing.T, root, revision, name, contains string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "revisions", revision, filepath.FromSlash(name)))
	if err != nil || !strings.Contains(string(data), contains) {
		t.Fatalf("public-site file %s = %q, %v; want content containing %q", name, data, err, contains)
	}
}

func uploadRequest(t *testing.T, handler http.Handler, cookie *http.Cookie, csrf string, archive []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("archive", "site.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(archive); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/web-content/upload", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("X-CSRF-Token", csrf)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func webContentTestZip(t *testing.T, homepage string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, value := range map[string]string{"index.html": homepage, "errors/403.html": "custom denied"} {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func jsonUnmarshal(data []byte, target any) error { return json.Unmarshal(data, target) }

func requestWithHeaders(handler http.Handler, method, path string, form url.Values, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	body := ""
	if form != nil {
		body = form.Encode()
	}
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
