package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"

	"github.com/Mytob/project_j/internal/webcontent"
)

func (s *Server) webContentStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); !ok {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	if s.webContentRoot == "" {
		http.Error(w, "Web content management is unavailable", http.StatusServiceUnavailable)
		return
	}
	status, err := webcontent.GetStatus(s.webContentRoot)
	if err != nil {
		http.Error(w, "Web content status is unavailable", http.StatusServiceUnavailable)
		return
	}
	writeWebContentJSON(w, status)
}

func (s *Server) uploadWebContent(w http.ResponseWriter, r *http.Request) {
	id, ok := s.session(r)
	if !ok {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	if !s.sessions.CheckCSRF(id, r.Header.Get("X-CSRF-Token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if s.webContentRoot == "" {
		http.Error(w, "Web content management is unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, webcontent.MaxArchiveBytes+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			http.Error(w, "Web content archive exceeds the upload limit", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "A valid ZIP archive is required", http.StatusBadRequest)
		}
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("archive")
	if err != nil {
		http.Error(w, "A web content ZIP archive is required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if header.Size <= 0 || header.Size > webcontent.MaxArchiveBytes || filepath.Ext(header.Filename) != ".zip" {
		http.Error(w, "Web content archive must be a ZIP file within the 25 MiB upload limit", http.StatusBadRequest)
		return
	}
	status, err := webcontent.PublishZip(s.webContentRoot, file, header.Size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeWebContentJSON(w, status)
}

func (s *Server) rollbackWebContent(w http.ResponseWriter, r *http.Request) {
	id, ok := s.session(r)
	if !ok {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	if !s.sessions.CheckCSRF(id, r.Header.Get("X-CSRF-Token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if s.webContentRoot == "" {
		http.Error(w, "Web content management is unavailable", http.StatusServiceUnavailable)
		return
	}
	status, err := webcontent.Rollback(s.webContentRoot)
	if err != nil {
		http.Error(w, "The previous public-site version could not be restored", http.StatusConflict)
		return
	}
	writeWebContentJSON(w, status)
}

func writeWebContentJSON(w http.ResponseWriter, status webcontent.Status) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(status)
}
