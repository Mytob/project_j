package maintenance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

const maxDownloadBytes = int64(2 << 30)

var ErrBackupNotFound = errors.New("backup not found")

type Client struct {
	origin string
	client *http.Client
}

func (c *Client) StartBackup(ctx context.Context) (Job, error) {
	return c.StartOperation(ctx, OperationRequest{Action: "backup"})
}

func (c *Client) StartOperation(ctx context.Context, operation OperationRequest) (Job, error) {
	encoded, err := json.Marshal(operation)
	if err != nil {
		return Job{}, errors.New("invalid maintenance operation")
	}
	body := strings.NewReader(string(encoded))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/system/jobs", body)
	if err != nil {
		return Job{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return Job{}, errors.New("private maintenance job service is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		if response.StatusCode == http.StatusConflict {
			return Job{}, ErrJobAlreadyRunning
		}
		return Job{}, errors.New("private maintenance job request was rejected")
	}
	var job Job
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<10))
	if err := decoder.Decode(&job); err != nil || !validClientJob(job) {
		return Job{}, errors.New("private maintenance job response was invalid")
	}
	return job, nil
}

func (c *Client) Jobs(ctx context.Context) ([]Job, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/system/jobs", nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, errors.New("private maintenance job service is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("private maintenance job service is unavailable")
	}
	var values []Job
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&values); err != nil || len(values) > 100 {
		return nil, errors.New("private maintenance job list was invalid")
	}
	for _, value := range values {
		if !validClientJob(value) {
			return nil, errors.New("private maintenance job list contained invalid data")
		}
	}
	return values, nil
}

func validClientJob(job Job) bool {
	if len(job.ID) != 32 || !validJobAction(job.Action) || !validJobState(job.State) || job.Total <= 0 || job.Total > 20 || job.Step < 0 || job.Step > job.Total || len(job.Message) > 200 || len(job.Result) > 255 || len(job.Error) > 240 || job.StartedAt.IsZero() || job.UpdatedAt.IsZero() {
		return false
	}
	_, err := hex.DecodeString(job.ID)
	return err == nil
}

func (c *Client) ValidateUpdate(ctx context.Context, uploadID, checksum string) (UpdateReview, error) {
	body, err := json.Marshal(struct {
		UploadID string `json:"upload_id"`
		SHA256   string `json:"sha256"`
	}{UploadID: uploadID, SHA256: checksum})
	if err != nil {
		return UpdateReview{}, errors.New("invalid package validation request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/system/packages/validate", strings.NewReader(string(body)))
	if err != nil {
		return UpdateReview{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return UpdateReview{}, errors.New("private package validation service is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return UpdateReview{}, errors.New("package is invalid or incompatible with the active release")
	}
	var review UpdateReview
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<10))
	if err := decoder.Decode(&review); err != nil || !validUpdateReview(review) {
		return UpdateReview{}, errors.New("private package validation response was invalid")
	}
	return review, nil
}

func (c *Client) ReleaseState(ctx context.Context) (ReleaseState, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/system/releases", nil)
	if err != nil {
		return ReleaseState{}, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return ReleaseState{}, errors.New("private release status service is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ReleaseState{}, errors.New("private release status service is unavailable")
	}
	var state ReleaseState
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<10))
	if err := decoder.Decode(&state); err != nil || !validReleaseState(state) {
		return ReleaseState{}, errors.New("private release status response was invalid")
	}
	return state, nil
}

func (c *Client) Recovery(ctx context.Context) (RecoveryStatus, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/system/recovery", nil)
	if err != nil {
		return RecoveryStatus{}, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return RecoveryStatus{}, errors.New("private service recovery status is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return RecoveryStatus{}, errors.New("private service recovery status is unavailable")
	}
	var status RecoveryStatus
	decoder := json.NewDecoder(io.LimitReader(response.Body, 256<<10))
	if err := decoder.Decode(&status); err != nil || !validRecoveryStatus(status) {
		return RecoveryStatus{}, errors.New("private service recovery response was invalid")
	}
	return status, nil
}

func validUpdateReview(value UpdateReview) bool {
	return value.CurrentVersion != "" && value.CurrentBuildID != "" && value.CandidateVersion != "" && value.CandidateBuildID != "" && value.TargetOS == "ubuntu-26.04" && value.Architecture == "amd64" && value.DatabaseSchemaMin > 0 && value.DatabaseSchemaMax >= value.DatabaseSchemaMin
}

func validReleaseState(value ReleaseState) bool {
	return value.Current.Version != "" && value.Current.BuildID != "" && ((value.Previous.Version == "" && value.Previous.BuildID == "") || (value.Previous.Version != "" && value.Previous.BuildID != ""))
}

func validRecoveryStatus(value RecoveryStatus) bool {
	if len(value.Services) != len(recoverableServices) || len(value.Events) > recoveryEventLimit {
		return false
	}
	seen := make(map[string]bool, len(value.Services))
	for _, service := range value.Services {
		if !allowedRecoveryService(service.Service) || seen[service.Service] || service.Attempts < 0 || service.Attempts > recoveryAttemptLimit || !validRecoveryText(service.State, 32) || !validRecoveryText(service.Health, 32) || !validRecoveryText(service.Detail, 160) || !validRecoveryAction(service.LastAction) {
			return false
		}
		seen[service.Service] = true
	}
	for _, event := range value.Events {
		if event.At.IsZero() || !allowedRecoveryService(event.Service) || !validRecoveryAction(event.Action) || event.Attempt < 0 || event.Attempt > recoveryAttemptLimit || !validRecoveryText(event.Detail, 160) {
			return false
		}
	}
	return true
}

func validRecoveryText(value string, maximum int) bool {
	return len(value) <= maximum && !strings.ContainsAny(value, "\r\n")
}

func validRecoveryAction(value string) bool {
	switch value {
	case "", "restart_requested", "restart_sent", "restart_failed", "retry_limit_reached", "recovered":
		return true
	default:
		return false
	}
}

func NewUnixClient(socketPath string) (*Client, error) {
	if !filepath.IsAbs(socketPath) || socketPath == "/" {
		return nil, errors.New("maintenance socket path must be absolute")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socketPath)
	}}
	return &Client{origin: "http://maintenance", client: &http.Client{Transport: transport, Timeout: 0}}, nil
}

func (c *Client) Backups(ctx context.Context) ([]BackupFile, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/system/backups", nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, errors.New("private backup listing service is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("private backup listing service is unavailable")
	}
	var values []BackupFile
	decoder := json.NewDecoder(io.LimitReader(response.Body, 256<<10))
	if err := decoder.Decode(&values); err != nil {
		return nil, errors.New("private backup listing was invalid")
	}
	if len(values) > 500 {
		return nil, errors.New("private backup listing exceeded its item limit")
	}
	for _, value := range values {
		if value.Name == "" || filepath.Base(value.Name) != value.Name || strings.ContainsAny(value.Name, "/\\") || filepath.Ext(value.Name) != ".bak" || value.SizeBytes <= 0 || value.SizeBytes > maxDownloadBytes || value.ModifiedAt.IsZero() {
			return nil, errors.New("private backup listing contained invalid metadata")
		}
	}
	return values, nil
}

func (c *Client) DownloadBackup(ctx context.Context, name string) (io.ReadCloser, int64, error) {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") || filepath.Ext(name) != ".bak" {
		return nil, 0, errors.New("invalid backup name")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/system/backups/"+name, nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, 0, errors.New("private backup download service is unavailable")
	}
	if response.StatusCode != http.StatusOK || response.ContentLength <= 0 || response.ContentLength > maxDownloadBytes {
		response.Body.Close()
		if response.StatusCode == http.StatusNotFound {
			return nil, 0, ErrBackupNotFound
		}
		return nil, 0, errors.New("private backup download service returned an invalid response")
	}
	return response.Body, response.ContentLength, nil
}
