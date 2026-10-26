package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/Mytob/project_j/internal/maintenance"
)

func (s *Server) systemBackups(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if s.systemMaintenance == nil {
		http.Error(w, "System maintenance is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	backups, err := s.systemMaintenance.Backups(ctx)
	if err != nil {
		http.Error(w, "Backup list is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(backups); err != nil {
		s.logger.Error("write backup list", "error", err)
	}
}

func (s *Server) downloadSystemBackup(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if s.systemMaintenance == nil {
		http.Error(w, "System maintenance is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Hour)
	defer cancel()
	name := r.PathValue("name")
	body, size, err := s.systemMaintenance.DownloadBackup(ctx, name)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, maintenance.ErrBackupNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, "Backup download is unavailable", status)
		return
	}
	defer body.Close()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Hour))
	contentDisposition := mime.FormatMediaType("attachment", map[string]string{"filename": name})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", contentDisposition)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := io.CopyN(w, body, size); err != nil {
		s.logger.Error("stream administrator backup download", "error", err)
	}
}

func (s *Server) systemJobs(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if s.systemMaintenance == nil {
		http.Error(w, "System maintenance is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	jobs, err := s.systemMaintenance.Jobs(ctx)
	if err != nil {
		http.Error(w, "Maintenance job status is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(jobs); err != nil {
		s.logger.Error("write maintenance job list", "error", err)
	}
}

func (s *Server) systemJob(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if s.systemMaintenance == nil {
		http.Error(w, "System maintenance is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	job, err := s.systemMaintenance.Job(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, "Maintenance job status is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(job); err != nil {
		s.logger.Error("write maintenance job status", "error", err)
	}
}

func (s *Server) startSystemJob(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	id, _ := s.session(r)
	if !s.sessions.CheckCSRF(id, r.Header.Get("X-CSRF-Token")) {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return
	}
	if s.systemMaintenance == nil {
		http.Error(w, "System maintenance is unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var operation maintenance.OperationRequest
	if err := decoder.Decode(&operation); err != nil || requireAdminJSONEOF(decoder) != nil {
		http.Error(w, "Invalid maintenance job request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	job, err := s.systemMaintenance.StartOperation(ctx, operation)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, maintenance.ErrJobAlreadyRunning) {
			status = http.StatusConflict
		}
		http.Error(w, "Backup job could not be started", status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) validateSystemPackage(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if !s.checkSystemCSRF(w, r) {
		return
	}
	if s.systemMaintenance == nil {
		http.Error(w, "System maintenance is unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request struct {
		UploadID string `json:"upload_id"`
		SHA256   string `json:"sha256"`
	}
	if err := decoder.Decode(&request); err != nil || requireAdminJSONEOF(decoder) != nil || !packageUploadIDPattern.MatchString(request.UploadID) || !packageChecksumPattern.MatchString(request.SHA256) {
		http.Error(w, "Invalid package validation request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	review, err := s.systemMaintenance.ValidateUpdate(ctx, request.UploadID, request.SHA256)
	if err != nil {
		http.Error(w, "Package is invalid or incompatible with the active release", http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(review)
}

func (s *Server) systemReleaseState(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if s.systemMaintenance == nil {
		http.Error(w, "System maintenance is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	state, err := s.systemMaintenance.ReleaseState(ctx)
	if err != nil {
		http.Error(w, "Release status is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(state)
}

func (s *Server) systemRecovery(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if s.systemMaintenance == nil {
		http.Error(w, "Service recovery status is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, err := s.systemMaintenance.Recovery(ctx)
	if err != nil {
		http.Error(w, "Service recovery status is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Server) createPackageUpload(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if !s.checkSystemCSRF(w, r) {
		return
	}
	if s.packageUploads == nil {
		http.Error(w, "Package uploads are unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request struct {
		Filename  string `json:"filename"`
		SizeBytes int64  `json:"size_bytes"`
	}
	if err := decoder.Decode(&request); err != nil || requireAdminJSONEOF(decoder) != nil {
		http.Error(w, "Invalid package upload request", http.StatusBadRequest)
		return
	}
	status, err := s.packageUploads.Create(request.Filename, request.SizeBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writePackageUploadStatus(w, http.StatusCreated, status)
}

func (s *Server) packageUploadStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if s.packageUploads == nil {
		http.Error(w, "Package uploads are unavailable", http.StatusServiceUnavailable)
		return
	}
	status, err := s.packageUploads.Status(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Package upload was not found", http.StatusNotFound)
		return
	}
	writePackageUploadStatus(w, http.StatusOK, status)
}

func (s *Server) putPackageUploadChunk(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if !s.checkSystemCSRF(w, r) {
		return
	}
	if s.packageUploads == nil {
		http.Error(w, "Package uploads are unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Minute))
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || index < 0 || index >= packageUploadMaxParts {
		http.Error(w, "Package upload chunk index is invalid", http.StatusBadRequest)
		return
	}
	if r.ContentLength > packageUploadChunkBytes+1 {
		http.Error(w, "Package upload chunk is too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, packageUploadChunkBytes+1)
	status, err := s.packageUploads.PutChunk(r.PathValue("id"), index, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writePackageUploadStatus(w, http.StatusOK, status)
}

func (s *Server) completePackageUpload(w http.ResponseWriter, r *http.Request) {
	if !s.requireFullAdminSession(w, r) {
		return
	}
	if !s.checkSystemCSRF(w, r) {
		return
	}
	if s.packageUploads == nil {
		http.Error(w, "Package uploads are unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request struct {
		SHA256 string `json:"sha256"`
	}
	if err := decoder.Decode(&request); err != nil || requireAdminJSONEOF(decoder) != nil {
		http.Error(w, "Invalid package checksum request", http.StatusBadRequest)
		return
	}
	status, err := s.packageUploads.Complete(r.PathValue("id"), request.SHA256)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writePackageUploadStatus(w, http.StatusOK, status)
}

func (s *Server) checkSystemCSRF(w http.ResponseWriter, r *http.Request) bool {
	id, _ := s.session(r)
	if !s.sessions.CheckCSRF(id, r.Header.Get("X-CSRF-Token")) {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return false
	}
	return true
}

func writePackageUploadStatus(w http.ResponseWriter, status int, value PackageUploadStatus) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) requireFullAdminSession(w http.ResponseWriter, r *http.Request) bool {
	id, authenticated := s.session(r)
	if !authenticated || s.sessions.EnrollmentOnly(id) {
		http.Error(w, "Administrator authentication is required", http.StatusUnauthorized)
		return false
	}
	return true
}
