package maintenance

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Mytob/project_j/internal/containerhealth"
)

const AuthorizedAdminUID = 65532
const DefaultBackupDirectory = "/var/backups/jellyfin-proxy"
const DefaultJobDirectory = "/var/lib/jellyfin-proxy-maintenance/jobs"
const DefaultPackageUploadDirectory = "/opt/jellyfin-proxy/data/package-uploads"

type peerKey struct{}

type Server struct {
	observer     *containerhealth.Observer
	backupRoot   string
	jobs         *JobManager
	createBackup func() (string, error)
	operations   Operations
	recovery     *RecoveryController
}

var versionOutputPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?$`)
var uploadIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var packageSHA256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var backupNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,180}\.bak$`)

func NewServer(dockerSocket string) *Server {
	return NewServerWithDirectories(dockerSocket, DefaultBackupDirectory, DefaultJobDirectory)
}

func NewServerWithBackupDirectory(dockerSocket, backupDirectory string) *Server {
	return NewServerWithDirectories(dockerSocket, backupDirectory, filepath.Join(backupDirectory, "jobs"))
}

func NewServerWithDirectories(dockerSocket, backupDirectory, jobDirectory string) *Server {
	return &Server{observer: containerhealth.New(dockerSocket), backupRoot: backupDirectory, jobs: NewJobManager(jobDirectory)}
}

// ConfigureBackupOperation binds the fixed privileged backup action before the
// HTTP server starts. The HTTP API cannot select a command or filesystem path.
func (s *Server) ConfigureBackupOperation(operation func() (string, error)) {
	s.createBackup = operation
}

func (s *Server) ConfigureOperations(operations Operations) {
	s.operations = operations
}

// Handler exposes container inventory and a fixed set of carefully validated
// host-maintenance operations. It has no raw Docker proxy, arbitrary command,
// caller-selected filesystem path, firewall, or shell endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r.Context()) {
			http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /containers", s.containers)
	mux.HandleFunc("GET /inventory", s.inventory)
	mux.HandleFunc("GET /system/backups", s.backups)
	mux.HandleFunc("GET /system/backups/{name}", s.downloadBackup)
	mux.HandleFunc("GET /system/releases", s.releaseState)
	mux.HandleFunc("GET /system/recovery", s.recoveryStatus)
	mux.HandleFunc("POST /system/packages/validate", s.validatePackage)
	mux.HandleFunc("POST /system/jobs", s.startJob)
	mux.HandleFunc("GET /system/jobs", s.listJobs)
	mux.HandleFunc("GET /system/jobs/{id}", s.getJob)
	return mux
}

func (s *Server) startJob(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	if r.ContentLength > 1024 {
		http.Error(w, "invalid maintenance job request", http.StatusBadRequest)
		return
	}
	var request struct {
		Action     string `json:"action"`
		UploadID   string `json:"upload_id,omitempty"`
		SHA256     string `json:"sha256,omitempty"`
		BackupName string `json:"backup_name,omitempty"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid maintenance job request", http.StatusBadRequest)
		return
	}
	if err := ensureJSONEOF(decoder); err != nil || validateOperationRequest(request.Action, request.UploadID, request.SHA256, request.BackupName) != nil {
		http.Error(w, "invalid maintenance job request", http.StatusBadRequest)
		return
	}
	if s.operations.Run == nil && (request.Action != "backup" || s.createBackup == nil) {
		http.Error(w, "maintenance operation is unavailable", http.StatusServiceUnavailable)
		return
	}
	total := operationTotal(request.Action)
	operation := OperationRequest{Action: request.Action, UploadID: request.UploadID, SHA256: strings.ToLower(request.SHA256), BackupName: request.BackupName}
	var maintenanceUpdated atomic.Bool
	operation.MaintenanceUpdated = func() { maintenanceUpdated.Store(true) }
	job, err := s.jobs.StartOperationWithCompletion(request.Action, total, func(report func(int, string)) (string, error) {
		if s.operations.Run == nil {
			report(1, "Creating and verifying backup")
			return s.createBackup()
		}
		return s.operations.Run(context.Background(), operation, func(progress OperationProgress) {
			report(progress.Step, progress.Message)
		})
	}, func(job Job) error {
		if !maintenanceUpdated.Load() {
			return nil
		}
		if s.operations.RestartMaintenance == nil {
			return errors.New("maintenance service refresh is unavailable")
		}
		return s.operations.RestartMaintenance(context.Background(), job.ID)
	})
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrJobAlreadyRunning) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(job)
}

func validateOperationRequest(action, uploadID, checksum, backupName string) error {
	switch action {
	case "backup", "cleanup", "rollback":
		if uploadID != "" || checksum != "" || backupName != "" {
			return errors.New("operation does not accept parameters")
		}
	case "update":
		if !uploadIDPattern.MatchString(uploadID) || !packageSHA256Pattern.MatchString(checksum) || backupName != "" {
			return errors.New("update requires an upload ID and independent checksum")
		}
	case "restore", "delete-backup":
		if !backupNamePattern.MatchString(backupName) || filepath.Base(backupName) != backupName || strings.ContainsAny(backupName, `/\\`) || uploadID != "" || checksum != "" {
			return errors.New("operation requires a stored backup file name")
		}
	default:
		return errors.New("unsupported maintenance operation")
	}
	return nil
}

func operationTotal(action string) int {
	switch action {
	case "backup":
		return 2
	case "cleanup":
		return 2
	case "update":
		return 8
	case "delete-backup":
		return 1
	case "restore", "rollback":
		return 7
	default:
		return 0
	}
}

func (s *Server) validatePackage(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	if s.operations.ValidateUpdate == nil {
		http.Error(w, "package validation is unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.ContentLength > 2048 {
		http.Error(w, "invalid package validation request", http.StatusBadRequest)
		return
	}
	var request struct {
		UploadID string `json:"upload_id"`
		SHA256   string `json:"sha256"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || ensureJSONEOF(decoder) != nil || !uploadIDPattern.MatchString(request.UploadID) || !packageSHA256Pattern.MatchString(request.SHA256) {
		http.Error(w, "invalid package validation request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	value, err := s.operations.ValidateUpdate(ctx, request.UploadID, strings.ToLower(request.SHA256))
	if err != nil {
		http.Error(w, "package is invalid or incompatible with the active release", http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) releaseState(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	if s.operations.ReleaseState == nil {
		http.Error(w, "release status is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	value, err := s.operations.ReleaseState(ctx)
	if err != nil {
		http.Error(w, "release status is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) recoveryStatus(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	if s.recovery == nil {
		http.Error(w, "service recovery status is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(s.recovery.Status())
}

func (s *Server) ConfigureRecovery(path string) error {
	controller, err := NewRecoveryController(s.observer, s.jobs, path)
	if err != nil {
		return err
	}
	s.recovery = controller
	return nil
}

func (s *Server) StartRecovery(ctx context.Context, interval time.Duration, onError func(error)) {
	if s.recovery == nil {
		return
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := s.recovery.RunOnce(ctx); err != nil && onError != nil {
				onError(err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	job, ok := s.jobs.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "maintenance job not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(s.jobs.List())
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON object")
	}
	return nil
}

type BackupFile struct {
	Name       string    `json:"name"`
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
}

func (s *Server) backups(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	info, err := os.Lstat(s.backupRoot)
	if errors.Is(err, os.ErrNotExist) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("[]\n"))
		return
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		http.Error(w, "backup store is unavailable", http.StatusServiceUnavailable)
		return
	}
	entries, err := os.ReadDir(s.backupRoot)
	if err != nil {
		http.Error(w, "backup store is unavailable", http.StatusServiceUnavailable)
		return
	}
	values := make([]BackupFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".bak" {
			continue
		}
		fileInfo, err := entry.Info()
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Size() <= 0 {
			continue
		}
		values = append(values, BackupFile{Name: entry.Name(), SizeBytes: fileInfo.Size(), ModifiedAt: fileInfo.ModTime().UTC()})
		if len(values) >= 500 {
			break
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ModifiedAt.After(values[j].ModifiedAt) })
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(values)
}

func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	name := r.PathValue("name")
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") || filepath.Ext(name) != ".bak" {
		http.Error(w, "backup not found", http.StatusNotFound)
		return
	}
	path := filepath.Join(s.backupRoot, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		http.Error(w, "backup not found", http.StatusNotFound)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		http.Error(w, "backup is unavailable", http.StatusServiceUnavailable)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) containers(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	values, err := s.observer.Snapshot(ctx)
	if err != nil {
		http.Error(w, "container health observation is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(values); err != nil {
		return
	}
}

func (s *Server) inventory(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Context()) {
		http.Error(w, "maintenance caller is not authorized", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	value := containerhealth.RuntimeInventory{}
	if hostVersion, err := readUbuntuVersion("/etc/os-release"); err == nil {
		value.UbuntuVersion = hostVersion
	}
	if version, err := runFixedVersionCommand(ctx, "/usr/local/sbin/proxyctl", "--version"); err == nil {
		value.ProxyctlVersion = version
	}
	if version, err := runFixedVersionCommand(ctx, "/usr/bin/docker", "compose", "version", "--short"); err == nil {
		value.ComposeVersion = version
	}
	observed, err := s.observer.Inventory(ctx)
	if err != nil {
		http.Error(w, "private runtime inventory is unavailable", http.StatusServiceUnavailable)
		return
	}
	value.DockerEngineVersion = observed.DockerEngineVersion
	value.Services = observed.Services
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(value)
}

func readUbuntuVersion(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || (resolved != path && resolved != "/usr/lib/os-release") {
		return "", errors.New("host release metadata is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32<<10 {
		return "", errors.New("host release metadata is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(io.LimitReader(file, 32<<10))
	scanner.Buffer(make([]byte, 1024), 8<<10)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || (key != "ID" && key != "PRETTY_NAME") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if values["ID"] != "ubuntu" || values["PRETTY_NAME"] == "" || len(values["PRETTY_NAME"]) > 160 || strings.ContainsAny(values["PRETTY_NAME"], "\r\n") {
		return "", errors.New("host is not identified as Ubuntu")
	}
	return values["PRETTY_NAME"], nil
}

func runFixedVersionCommand(ctx context.Context, executable string, args ...string) (string, error) {
	if !filepath.IsAbs(executable) {
		return "", errors.New("version executable path is not absolute")
	}
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("version executable is unavailable")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	if len(value) > 128 || !versionOutputPattern.MatchString(value) {
		if strings.HasPrefix(value, "proxyctl ") {
			value = strings.TrimSpace(strings.TrimPrefix(value, "proxyctl "))
		}
	}
	if len(value) > 128 || !versionOutputPattern.MatchString(value) {
		return "", errors.New("fixed version command returned an invalid version")
	}
	return value, nil
}

func WithPeerUID(ctx context.Context, uid uint32) context.Context {
	return context.WithValue(ctx, peerKey{}, uid)
}

func authorized(ctx context.Context) bool {
	uid, ok := ctx.Value(peerKey{}).(uint32)
	return ok && uid == AuthorizedAdminUID
}

// Serve listens only on a Unix socket. The listener creates a fresh HTTP
// request context carrying the peer credentials for every accepted connection.
func Serve(listener net.Listener, handler http.Handler, peerUID func(net.Conn) (uint32, error)) error {
	if listener == nil || handler == nil || peerUID == nil {
		return errors.New("maintenance socket server requires listener, handler, and peer credential reader")
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       6 * time.Second,
		WriteTimeout:      6 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			uid, err := peerUID(connection)
			if err != nil {
				return ctx
			}
			return WithPeerUID(ctx, uid)
		},
	}
	return server.Serve(listener)
}
