package admin

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mytob/project_j/internal/maintenance"
)

func TestSystemBackupEndpointsRequireFullAdminSession(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix maintenance socket is Linux-only")
	}
	backupRoot := t.TempDir()
	if err := os.Chmod(backupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "jellyfin-proxy-1.6.0-20261022.bak"
	content := []byte("system-backup-test")
	if err := os.WriteFile(filepath.Join(backupRoot, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
	maintenanceServer := maintenance.NewServerWithBackupDirectory(filepath.Join(t.TempDir(), "missing-docker.sock"), backupRoot)
	maintenanceServer.ConfigureBackupOperation(func() (string, error) { return "admin-test.bak", nil })
	socketPath := filepath.Join(t.TempDir(), "maintenance.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = maintenance.Serve(listener, maintenanceServer.Handler(), func(net.Conn) (uint32, error) {
			return maintenance.AuthorizedAdminUID, nil
		})
	}()
	defer listener.Close()
	client, err := maintenance.NewUnixClient(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server, _, _, _ := newTOTPTestServer(t)
	server.systemMaintenance = client
	handler := server.Handler()

	unauthenticated := httptest.NewRequest(http.MethodGet, "/system/backups", nil)
	unauthenticatedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticatedResponse, unauthenticated)
	if unauthenticatedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous backup listing status = %d, want 401", unauthenticatedResponse.Code)
	}

	sessionID, csrf, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/system/backups", nil)
	request.AddCookie(&http.Cookie{Name: "admin_session", Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), name) {
		t.Fatalf("authenticated backup listing = %d %q", response.Code, response.Body.String())
	}

	jobs := httptest.NewRequest(http.MethodGet, "/system/jobs", nil)
	jobs.AddCookie(&http.Cookie{Name: "admin_session", Value: sessionID})
	jobsResponse := httptest.NewRecorder()
	handler.ServeHTTP(jobsResponse, jobs)
	if jobsResponse.Code != http.StatusOK || strings.TrimSpace(jobsResponse.Body.String()) != "[]" {
		t.Fatalf("authenticated job listing = %d %q", jobsResponse.Code, jobsResponse.Body.String())
	}

	startWithoutCSRF := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(`{"action":"backup"}`))
	startWithoutCSRF.AddCookie(&http.Cookie{Name: "admin_session", Value: sessionID})
	withoutCSRFResponse := httptest.NewRecorder()
	handler.ServeHTTP(withoutCSRFResponse, startWithoutCSRF)
	if withoutCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("backup job without CSRF = %d, want 403", withoutCSRFResponse.Code)
	}

	start := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(`{"action":"backup"}`))
	start.AddCookie(&http.Cookie{Name: "admin_session", Value: sessionID})
	start.Header.Set("X-CSRF-Token", csrf)
	startResponse := httptest.NewRecorder()
	handler.ServeHTTP(startResponse, start)
	if startResponse.Code != http.StatusAccepted || !strings.Contains(startResponse.Body.String(), `"action":"backup"`) {
		t.Fatalf("authenticated backup job start = %d %q", startResponse.Code, startResponse.Body.String())
	}

	download := httptest.NewRequest(http.MethodGet, "/system/backups/"+name, nil)
	download.AddCookie(&http.Cookie{Name: "admin_session", Value: sessionID})
	downloadResponse := httptest.NewRecorder()
	handler.ServeHTTP(downloadResponse, download)
	if downloadResponse.Code != http.StatusOK || downloadResponse.Body.String() != string(content) {
		t.Fatalf("authenticated backup download = %d %q", downloadResponse.Code, downloadResponse.Body.String())
	}
	enrollmentID, _, err := server.sessions.CreateEnrollmentOnly()
	if err != nil {
		t.Fatal(err)
	}
	enrollment := httptest.NewRequest(http.MethodGet, "/system/backups", nil)
	enrollment.AddCookie(&http.Cookie{Name: "admin_session", Value: enrollmentID})
	enrollmentResponse := httptest.NewRecorder()
	handler.ServeHTTP(enrollmentResponse, enrollment)
	if enrollmentResponse.Code != http.StatusUnauthorized {
		t.Fatalf("enrollment-only backup listing status = %d, want 401", enrollmentResponse.Code)
	}
}
