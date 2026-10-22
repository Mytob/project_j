package maintenance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandlerAuthorizesHealthEndpointByPeerUID(t *testing.T) {
	server := NewServer(t.TempDir() + "/missing-docker.sock")
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request = request.WithContext(WithPeerUID(request.Context(), AuthorizedAdminUID))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("authorized health request: code %d, body %q", response.Code, response.Body.String())
	}
}

func TestHandlerRejectsUnauthorizedCallerAndUnsupportedOperations(t *testing.T) {
	server := NewServer(t.TempDir() + "/missing-docker.sock")
	for _, test := range []struct {
		name   string
		method string
		path   string
		uid    *uint32
		want   int
	}{
		{name: "missing credentials", method: http.MethodGet, path: "/healthz", want: http.StatusForbidden},
		{name: "wrong uid", method: http.MethodGet, path: "/containers", uid: uid(0), want: http.StatusForbidden},
		{name: "arbitrary docker endpoint", method: http.MethodGet, path: "/v1.41/containers/json", uid: uid(AuthorizedAdminUID), want: http.StatusNotFound},
		{name: "mutation endpoint", method: http.MethodPost, path: "/containers", uid: uid(AuthorizedAdminUID), want: http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			if test.uid != nil {
				request = request.WithContext(WithPeerUID(context.Background(), *test.uid))
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestBackupListingAndDownloadAreAdminUIDOnlyAndPathBounded(t *testing.T) {
	backupRoot := t.TempDir()
	if err := os.Chmod(backupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "jellyfin-proxy-1.6.0-20261022.bak"
	content := []byte("verified-test-backup")
	if err := os.WriteFile(filepath.Join(backupRoot, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
	server := NewServer(filepath.Join(t.TempDir(), "missing-docker.sock"))
	server.backupRoot = backupRoot
	handler := server.Handler()

	unauthorized := httptest.NewRequest(http.MethodGet, "/system/backups", nil)
	unauthorized = unauthorized.WithContext(WithPeerUID(unauthorized.Context(), 1234))
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, unauthorized)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("untrusted backup listing status = %d, want 403", denied.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/system/backups", nil)
	request = request.WithContext(WithPeerUID(request.Context(), AuthorizedAdminUID))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var entries []BackupFile
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &entries) != nil || len(entries) != 1 || entries[0].Name != name || entries[0].SizeBytes != int64(len(content)) {
		t.Fatalf("backup listing response = %d %q, entries=%+v", response.Code, response.Body.String(), entries)
	}

	download := httptest.NewRequest(http.MethodGet, "/system/backups/"+name, nil)
	download = download.WithContext(WithPeerUID(download.Context(), AuthorizedAdminUID))
	downloadResponse := httptest.NewRecorder()
	handler.ServeHTTP(downloadResponse, download)
	if downloadResponse.Code != http.StatusOK || downloadResponse.Body.String() != string(content) || !strings.Contains(downloadResponse.Header().Get("Content-Disposition"), name) {
		t.Fatalf("backup download response = %d %q headers=%v", downloadResponse.Code, downloadResponse.Body.String(), downloadResponse.Header())
	}

	traversal := httptest.NewRequest(http.MethodGet, "/system/backups/%2e%2e%2fetc%2fpasswd.bak", nil)
	traversal = traversal.WithContext(WithPeerUID(traversal.Context(), AuthorizedAdminUID))
	traversalResponse := httptest.NewRecorder()
	handler.ServeHTTP(traversalResponse, traversal)
	if traversalResponse.Code != http.StatusNotFound {
		t.Fatalf("backup traversal status = %d, want 404", traversalResponse.Code)
	}

	link := filepath.Join(backupRoot, "linked.bak")
	if err := os.Symlink(filepath.Join(backupRoot, name), link); err != nil {
		t.Fatal(err)
	}
	linkRequest := httptest.NewRequest(http.MethodGet, "/system/backups/linked.bak", nil)
	linkRequest = linkRequest.WithContext(WithPeerUID(linkRequest.Context(), AuthorizedAdminUID))
	linkResponse := httptest.NewRecorder()
	handler.ServeHTTP(linkResponse, linkRequest)
	if linkResponse.Code != http.StatusNotFound {
		t.Fatalf("backup symlink download status = %d, want 404", linkResponse.Code)
	}
}

func TestMissingBackupStoreIsAnEmptyListing(t *testing.T) {
	server := NewServer(filepath.Join(t.TempDir(), "missing-docker.sock"))
	server.backupRoot = filepath.Join(t.TempDir(), "missing-backups")
	request := httptest.NewRequest(http.MethodGet, "/system/backups", nil)
	request = request.WithContext(WithPeerUID(request.Context(), AuthorizedAdminUID))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != "[]" {
		t.Fatalf("missing backup store response = %d %q", response.Code, response.Body.String())
	}
}

func TestMaintenanceJobsRequireAdminAndFixedRequest(t *testing.T) {
	jobRoot := filepath.Join(t.TempDir(), "jobs")
	server := NewServerWithDirectories(filepath.Join(t.TempDir(), "missing-docker.sock"), filepath.Join(t.TempDir(), "backups"), jobRoot)
	server.ConfigureBackupOperation(func() (string, error) { return "manual-test.bak", nil })
	handler := server.Handler()

	unauthorized := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(`{"action":"backup"}`))
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, unauthorized)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unauthorized job start = %d, want 403", denied.Code)
	}

	for _, body := range []string{`{"action":"restore"}`, `{"action":"backup","path":"/etc/passwd"}`, `{"action":"cleanup","backup_name":"anything.bak"}`, `{"action":"backup"} {}`} {
		request := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(body))
		request = request.WithContext(WithPeerUID(request.Context(), AuthorizedAdminUID))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid operation %q status = %d, want 400", body, response.Code)
		}
	}
	valid := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(`{"action":"backup"}`))
	valid = valid.WithContext(WithPeerUID(valid.Context(), AuthorizedAdminUID))
	started := httptest.NewRecorder()
	handler.ServeHTTP(started, valid)
	if started.Code != http.StatusAccepted {
		t.Fatalf("fixed backup job start = %d %q, want 202", started.Code, started.Body.String())
	}
	var job Job
	if err := json.Unmarshal(started.Body.Bytes(), &job); err != nil || job.Action != "backup" || job.State != "queued" {
		t.Fatalf("accepted job response = %+v, error=%v", job, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if current, ok := server.jobs.Get(job.ID); ok && current.State == "completed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if completed, _ := server.jobs.Get(job.ID); completed.State != "completed" || completed.Result != "manual-test.bak" {
		t.Fatalf("fixed backup job result = %+v", completed)
	}

	list := httptest.NewRequest(http.MethodGet, "/system/jobs", nil)
	list = list.WithContext(WithPeerUID(list.Context(), 0))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, list)
	if response.Code != http.StatusForbidden {
		t.Fatalf("root job listing = %d, want 403", response.Code)
	}
}

func TestMaintenanceCleanupJobUsesFixedNoArgumentAction(t *testing.T) {
	server := NewServerWithDirectories(filepath.Join(t.TempDir(), "missing-docker.sock"), filepath.Join(t.TempDir(), "backups"), filepath.Join(t.TempDir(), "jobs"))
	var invoked bool
	server.ConfigureOperations(Operations{Run: func(_ context.Context, operation OperationRequest, report func(OperationProgress)) (string, error) {
		if operation.Action != "cleanup" || operation.UploadID != "" || operation.SHA256 != "" || operation.BackupName != "" {
			t.Fatalf("cleanup received caller-controlled arguments: %+v", operation)
		}
		invoked = true
		report(OperationProgress{Step: 2, Total: 2, Message: "Cleanup complete"})
		return "Removed 2 unused image(s); kept 10 protected or in-use image(s)", nil
	}})
	handler := server.Handler()

	for _, body := range []string{
		`{"action":"cleanup","upload_id":"0123456789abcdef0123456789abcdef"}`,
		`{"action":"cleanup","sha256":"` + strings.Repeat("a", 64) + `"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(body))
		request = request.WithContext(WithPeerUID(request.Context(), AuthorizedAdminUID))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("cleanup with caller-controlled argument %q returned %d, want 400", body, response.Code)
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(`{"action":"cleanup"}`))
	request = request.WithContext(WithPeerUID(request.Context(), AuthorizedAdminUID))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("fixed cleanup job start = %d %q, want 202", response.Code, response.Body.String())
	}
	var job Job
	if err := json.Unmarshal(response.Body.Bytes(), &job); err != nil || job.Action != "cleanup" || job.Total != 2 {
		t.Fatalf("cleanup job response = %+v, %v", job, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if current, ok := server.jobs.Get(job.ID); ok && current.State == "completed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	completed, _ := server.jobs.Get(job.ID)
	if !invoked || completed.State != "completed" || !strings.Contains(completed.Result, "Removed 2 unused") {
		t.Fatalf("cleanup job did not finish through fixed callback: %+v, invoked=%v", completed, invoked)
	}
}

func TestMaintenanceServiceRefreshRunsAfterPersistedJobCompletion(t *testing.T) {
	server := NewServerWithDirectories(filepath.Join(t.TempDir(), "missing-docker.sock"), filepath.Join(t.TempDir(), "backups"), filepath.Join(t.TempDir(), "jobs"))
	refreshed := make(chan string, 1)
	server.ConfigureOperations(Operations{
		Run: func(_ context.Context, operation OperationRequest, _ func(OperationProgress)) (string, error) {
			if operation.Action != "update" || operation.MaintenanceUpdated == nil {
				t.Fatalf("update did not receive the internal service refresh signal: %+v", operation)
			}
			operation.MaintenanceUpdated()
			return "1.6.0-dev.7", nil
		},
		RestartMaintenance: func(_ context.Context, jobID string) error {
			reloaded := NewJobManager(server.jobs.dir)
			job, ok := reloaded.Get(jobID)
			if !ok || job.State != "completed" || job.Result != "1.6.0-dev.7" {
				return fmt.Errorf("service refresh ran before completed job was persisted: %+v, found=%v", job, ok)
			}
			refreshed <- jobID
			return nil
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(`{"action":"update","upload_id":"0123456789abcdef0123456789abcdef","sha256":"`+strings.Repeat("a", 64)+`"}`))
	request = request.WithContext(WithPeerUID(request.Context(), AuthorizedAdminUID))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("update job start = %d %q", response.Code, response.Body.String())
	}
	var started Job
	if err := json.Unmarshal(response.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	select {
	case jobID := <-refreshed:
		if jobID != started.ID {
			t.Fatalf("refresh scheduled for job %s, want %s", jobID, started.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance service refresh hook did not run")
	}
}

func TestMaintenanceUpdateReviewAndJobsUseOnlyFixedValidatedInputs(t *testing.T) {
	server := NewServerWithDirectories(filepath.Join(t.TempDir(), "missing-docker.sock"), filepath.Join(t.TempDir(), "backups"), filepath.Join(t.TempDir(), "jobs"))
	var runRequest OperationRequest
	validatedID := ""
	server.ConfigureOperations(Operations{
		ValidateUpdate: func(_ context.Context, id, checksum string) (UpdateReview, error) {
			validatedID = id + ":" + checksum
			return UpdateReview{CurrentVersion: "1.6.0-dev.5", CurrentBuildID: "current", CandidateVersion: "1.6.0-dev.6", CandidateBuildID: "candidate", TargetOS: "ubuntu-26.04", Architecture: "amd64", DatabaseSchemaMin: 2, DatabaseSchemaMax: 2}, nil
		},
		ReleaseState: func(context.Context) (ReleaseState, error) {
			return ReleaseState{Current: ReleaseVersion{Version: "1.6.0-dev.5", BuildID: "current"}, Previous: ReleaseVersion{Version: "1.6.0-dev.4", BuildID: "previous"}}, nil
		},
		Run: func(_ context.Context, operation OperationRequest, report func(OperationProgress)) (string, error) {
			runRequest = operation
			report(OperationProgress{Step: 8, Total: 8, Message: "Update verified"})
			return "1.6.0-dev.6 · candidate", nil
		},
	})
	handler := server.Handler()
	id := "0123456789abcdef0123456789abcdef"
	checksum := strings.Repeat("a", 64)

	unauthorized := httptest.NewRequest(http.MethodPost, "/system/packages/validate", strings.NewReader(`{"upload_id":"`+id+`","sha256":"`+checksum+`"}`))
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, unauthorized)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("anonymous package validation status = %d, want 403", denied.Code)
	}

	for _, body := range []string{
		`{"upload_id":"` + id + `"}`,
		`{"upload_id":"../` + id + `","sha256":"` + checksum + `"}`,
		`{"upload_id":"` + id + `","sha256":"` + checksum + `","path":"/etc/passwd"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/system/packages/validate", strings.NewReader(body))
		request = request.WithContext(WithPeerUID(request.Context(), AuthorizedAdminUID))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("invalid package validation request %q status = %d, want 400", body, response.Code)
		}
	}

	validate := httptest.NewRequest(http.MethodPost, "/system/packages/validate", strings.NewReader(`{"upload_id":"`+id+`","sha256":"`+checksum+`"}`))
	validate = validate.WithContext(WithPeerUID(validate.Context(), AuthorizedAdminUID))
	validated := httptest.NewRecorder()
	handler.ServeHTTP(validated, validate)
	if validated.Code != http.StatusOK || !strings.Contains(validated.Body.String(), `"candidate_version":"1.6.0-dev.6"`) || validatedID != id+":"+checksum {
		t.Fatalf("package compatibility review = %d %q, callback %q", validated.Code, validated.Body.String(), validatedID)
	}

	releases := httptest.NewRequest(http.MethodGet, "/system/releases", nil)
	releases = releases.WithContext(WithPeerUID(releases.Context(), AuthorizedAdminUID))
	releaseResponse := httptest.NewRecorder()
	handler.ServeHTTP(releaseResponse, releases)
	if releaseResponse.Code != http.StatusOK || !strings.Contains(releaseResponse.Body.String(), `"previous"`) {
		t.Fatalf("release state = %d %q", releaseResponse.Code, releaseResponse.Body.String())
	}

	invalidUpdate := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(`{"action":"update","upload_id":"`+id+`"}`))
	invalidUpdate = invalidUpdate.WithContext(WithPeerUID(invalidUpdate.Context(), AuthorizedAdminUID))
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalidUpdate)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("update without independent checksum = %d, want 400", invalidResponse.Code)
	}

	update := httptest.NewRequest(http.MethodPost, "/system/jobs", strings.NewReader(`{"action":"update","upload_id":"`+id+`","sha256":"`+checksum+`"}`))
	update = update.WithContext(WithPeerUID(update.Context(), AuthorizedAdminUID))
	started := httptest.NewRecorder()
	handler.ServeHTTP(started, update)
	if started.Code != http.StatusAccepted {
		t.Fatalf("valid update job = %d %q", started.Code, started.Body.String())
	}
	var job Job
	if err := json.Unmarshal(started.Body.Bytes(), &job); err != nil || job.Action != "update" {
		t.Fatalf("update job response = %+v, %v", job, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if current, ok := server.jobs.Get(job.ID); ok && current.State == "completed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	completed, _ := server.jobs.Get(job.ID)
	if completed.State != "completed" || completed.Result != "1.6.0-dev.6 · candidate" || runRequest.Action != "update" || runRequest.UploadID != id || runRequest.SHA256 != checksum {
		t.Fatalf("fixed update job result = %+v, operation=%+v", completed, runRequest)
	}
}

func uid(value uint32) *uint32 { return &value }
