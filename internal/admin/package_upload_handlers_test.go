package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mytob/project_j/internal/auth"
)

func TestPackageUploadHandlersRequireAdminCSRFAndPersistChunks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	if err := auth.SaveCredential(path, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	server := New(credential, nil)
	if err := server.ConfigurePackageUploads(filepath.Join(t.TempDir(), "uploads")); err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	cookie := loginTestAdmin(t, server)
	bootstrap := request(handler, http.MethodGet, "/api/initial", nil, cookie)
	var initial struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(bootstrap.Body.Bytes(), &initial); err != nil || initial.CSRF == "" {
		t.Fatalf("bootstrap CSRF = %q, %v", initial.CSRF, err)
	}

	create := httptest.NewRequest(http.MethodPost, "/system/uploads", strings.NewReader(`{"filename":"candidate.pkg","size_bytes":5}`))
	create.AddCookie(cookie)
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("X-CSRF-Token", initial.CSRF)
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create upload = %d %q", created.Code, created.Body.String())
	}
	var status PackageUploadStatus
	if err := json.Unmarshal(created.Body.Bytes(), &status); err != nil || status.ID == "" {
		t.Fatalf("created upload status = %+v, %v", status, err)
	}

	missingCSRF := httptest.NewRequest(http.MethodPut, "/system/uploads/"+status.ID+"/0", bytes.NewReader([]byte("hello")))
	missingCSRF.AddCookie(cookie)
	missingCSRFRecorder := httptest.NewRecorder()
	handler.ServeHTTP(missingCSRFRecorder, missingCSRF)
	if missingCSRFRecorder.Code != http.StatusForbidden {
		t.Fatalf("chunk without CSRF = %d, want 403", missingCSRFRecorder.Code)
	}

	put := httptest.NewRequest(http.MethodPut, "/system/uploads/"+status.ID+"/0", bytes.NewReader([]byte("hello")))
	put.AddCookie(cookie)
	put.Header.Set("X-CSRF-Token", initial.CSRF)
	putRecorder := httptest.NewRecorder()
	handler.ServeHTTP(putRecorder, put)
	if putRecorder.Code != http.StatusOK {
		t.Fatalf("upload chunk = %d %q", putRecorder.Code, putRecorder.Body.String())
	}

	statusRequest := httptest.NewRequest(http.MethodGet, "/system/uploads/"+status.ID, nil)
	statusRequest.AddCookie(cookie)
	statusRecorder := httptest.NewRecorder()
	handler.ServeHTTP(statusRecorder, statusRequest)
	if statusRecorder.Code != http.StatusOK || !strings.Contains(statusRecorder.Body.String(), `"received_chunks":[0]`) {
		t.Fatalf("resumed upload status = %d %q", statusRecorder.Code, statusRecorder.Body.String())
	}
}

func TestPackageUploadHandlersRejectAnonymousAndUnconfiguredRequests(t *testing.T) {
	handler := newTestServer(t)
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/system/uploads/0123456789abcdef0123456789abcdef"},
		{http.MethodPost, "/system/uploads"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s = %d, want 401", test.method, test.path, response.Code)
		}
	}
}
