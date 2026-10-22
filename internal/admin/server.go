package admin

import (
	"context"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/containerhealth"
	"github.com/Mytob/project_j/internal/maintenance"
	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/security"
	"github.com/Mytob/project_j/internal/webcontent"
	"github.com/Mytob/project_j/internal/whitelist"
	"github.com/Mytob/project_j/internal/wireguard"
	"github.com/skip2/go-qrcode"
)

//go:embed templates/* frontend/dist
var templateFiles embed.FS

type Server struct {
	credential               *auth.Credential
	sessions                 *auth.Sessions
	totpStore                *auth.TOTPStore
	limiter                  *auth.LoginLimiter
	passwordLimiter          *auth.LoginLimiter
	credentialPath           string
	healthStatePath          string
	healthMu                 sync.Mutex
	healthRecords            map[string]healthRecord
	healthEvents             []healthEvent
	componentHealthMu        sync.Mutex
	componentHealthAt        time.Time
	componentHealthCache     []componentStatus
	componentHealthWireGuard *wireguard.PeerStatus
	cpuPressure              cpuPressureState
	whitelist                *WhitelistManager
	wireguardClientConfig    string
	wireguardConfigMu        sync.Mutex
	wireguardControl         wireguard.ControlClient
	wireguardEndpoint        string
	wireguardKeepalive       uint16
	templates                *template.Template
	logger                   *slog.Logger
	now                      func() time.Time
	authTransitionMu         sync.Mutex
	version                  string
	buildNumber              string
	statistics               *monitoring.Feed
	caddyHealth              interface{ CheckHealth() error }
	containerHealth          *containerhealth.Client
	systemMaintenance        *maintenance.Client
	wireguardHealthPath      string
	securityEventDir         string
	securityEventKey         []byte
	trustedProxyNetworks     []netip.Prefix
	securityControl          *security.Client
	securityEventHealthy     atomic.Bool
	webContentRoot           string
	installMetadataPath      string
	packageUploads           *PackageUploadStore
}

const totpReauthenticationLifetime = 5 * time.Minute

func New(credential *auth.Credential, logger *slog.Logger, whitelistManager ...*WhitelistManager) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	server := &Server{credential: credential, sessions: auth.NewSessions(auth.DefaultSessionLifetime), limiter: auth.NewLoginLimiter(0, 0), passwordLimiter: auth.NewLoginLimiter(0, 0), templates: template.Must(template.ParseFS(templateFiles, "templates/*.html")), logger: logger, now: time.Now, version: "development", buildNumber: "unknown"}
	if len(whitelistManager) > 0 {
		server.whitelist = whitelistManager[0]
	}
	return server
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	frontend, err := fs.Sub(templateFiles, "frontend/dist")
	if err != nil {
		panic(err)
	}
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /assets/admin.css", s.stylesheet)
	mux.HandleFunc("GET /assets/statistics.js", s.statisticsScript)
	mux.Handle("GET /app-assets/", http.StripPrefix("/app-assets/", http.FileServer(http.FS(frontend))))
	mux.HandleFunc("GET /api/initial", s.apiInitial)
	mux.HandleFunc("GET /api/about", s.apiAbout)
	mux.HandleFunc("GET /", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("POST /totp/enroll/start", s.startTOTPEnrollment)
	mux.HandleFunc("POST /totp/enroll/confirm", s.confirmTOTPEnrollmentHandler)
	mux.HandleFunc("POST /totp/enroll/cancel", s.cancelTOTPEnrollment)
	mux.HandleFunc("POST /totp/disable", s.disableTOTP)
	mux.HandleFunc("POST /password/change", s.changePassword)
	mux.HandleFunc("GET /dashboard", s.dashboard)
	mux.HandleFunc("GET /web-content", s.dashboard)
	mux.HandleFunc("GET /about", s.dashboard)
	mux.HandleFunc("GET /system", s.dashboard)
	mux.HandleFunc("GET /settings", s.dashboard)
	mux.HandleFunc("GET /health", s.healthPage)
	mux.HandleFunc("GET /access-control", s.accessControlPage)
	mux.HandleFunc("GET /security", s.securityPage)
	mux.HandleFunc("GET /wireguard", s.wireGuardPage)
	mux.HandleFunc("GET /statistics", s.statisticsPage)
	mux.HandleFunc("GET /statistics/events", s.statisticsEvents)
	mux.HandleFunc("GET /statistics/history", s.statisticsHistory)
	mux.HandleFunc("GET /statistics/settings", s.statisticsSettings)
	mux.HandleFunc("POST /statistics/settings", s.updateStatisticsSettings)
	mux.HandleFunc("GET /web-content/status", s.webContentStatus)
	mux.HandleFunc("POST /web-content/upload", s.uploadWebContent)
	mux.HandleFunc("POST /web-content/rollback", s.rollbackWebContent)
	mux.HandleFunc("GET /system/backups", s.systemBackups)
	mux.HandleFunc("GET /system/backups/{name}", s.downloadSystemBackup)
	mux.HandleFunc("POST /system/uploads", s.createPackageUpload)
	mux.HandleFunc("GET /system/uploads/{id}", s.packageUploadStatus)
	mux.HandleFunc("PUT /system/uploads/{id}/{index}", s.putPackageUploadChunk)
	mux.HandleFunc("POST /system/uploads/{id}/complete", s.completePackageUpload)
	mux.HandleFunc("GET /system/jobs", s.systemJobs)
	mux.HandleFunc("POST /system/jobs", s.startSystemJob)
	mux.HandleFunc("GET /system/releases", s.systemReleaseState)
	mux.HandleFunc("GET /system/recovery", s.systemRecovery)
	mux.HandleFunc("POST /system/packages/validate", s.validateSystemPackage)
	mux.HandleFunc("GET /security/history", s.securityHistory)
	mux.HandleFunc("POST /security/config", s.updateSecurityConfig)
	mux.HandleFunc("POST /security/unban", s.unbanSecurityIP)
	mux.HandleFunc("POST /whitelist/add", s.addWhitelistEntry)
	mux.HandleFunc("POST /whitelist/name", s.nameWhitelistEntry)
	mux.HandleFunc("POST /whitelist/remove", s.removeWhitelistEntry)
	mux.HandleFunc("POST /wireguard/config", s.downloadWireGuardConfig)
	mux.HandleFunc("POST /wireguard/rotate", s.rotateWireGuardConfig)
	return s.securityHeaders(mux)
}

// ConfigureWebContent sets the persistent, isolated static-site root shared
// read-only with Caddy. The administrator process writes only this subtree.
func (s *Server) ConfigureWebContent(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
		return errors.New("web content root must be an absolute non-root path")
	}
	s.webContentRoot = filepath.Clean(root)
	if err := webcontent.EnsureDefaultErrorPages(s.webContentRoot); err != nil {
		return fmt.Errorf("migrate built-in public error pages: %w", err)
	}
	return nil
}

func (s *Server) ConfigureInstallMetadata(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return errors.New("installation metadata path must be absolute")
	}
	s.installMetadataPath = filepath.Clean(path)
	return nil
}

// ConfigureCredentialPath sets the persistent override path used when an
// administrator changes their password in the web interface.
func (s *Server) ConfigureCredentialPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("administrator credential path is empty")
	}
	s.credentialPath = path
	return nil
}

// ConfigureHealthState enables private persistent health transition history.
func (s *Server) ConfigureHealthState(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("health state path is empty")
	}
	if err := s.loadHealthState(path); err != nil {
		return err
	}
	s.healthStatePath = path
	return nil
}

func (s *Server) stylesheet(w http.ResponseWriter, _ *http.Request) {
	data, err := templateFiles.ReadFile("templates/admin.css")
	if err != nil {
		http.Error(w, "Stylesheet unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) statisticsScript(w http.ResponseWriter, _ *http.Request) {
	data, err := templateFiles.ReadFile("templates/statistics.js")
	if err != nil {
		http.Error(w, "Statistics script unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) adminAppIndex(w http.ResponseWriter) bool {
	data, err := templateFiles.ReadFile("frontend/dist/index.html")
	if err != nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	return true
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// ConfigureWireGuardConfig verifies the protected retained Windows peer file
// before making it available to authenticated administrators.
func (s *Server) ConfigureWireGuardConfig(path string) error {
	if path == "" {
		return errors.New("Windows WireGuard configuration path is empty")
	}
	if _, err := wireguard.LoadRetainedClientConfig(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.wireguardClientConfig = path
	return nil
}

// ConfigureWireGuardControl attaches the private local control socket used for
// peer rotation. The socket is mounted only into the isolated admin and
// WireGuard services; it is never published over TCP.
func (s *Server) ConfigureWireGuardControl(socketPath, endpoint string, keepalive uint16) error {
	if socketPath == "" || strings.TrimSpace(endpoint) == "" || keepalive == 0 {
		return errors.New("WireGuard control socket, endpoint and keepalive are required")
	}
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		return errors.New("WireGuard client endpoint is invalid")
	}
	s.wireguardControl = wireguard.ControlClient{SocketPath: socketPath}
	s.wireguardEndpoint = endpoint
	s.wireguardKeepalive = keepalive
	s.invalidateComponentHealth()
	return nil
}

// ConfigureTOTPStore connects validated persistent TOTP state to the admin
// authentication boundary.
func (s *Server) ConfigureTOTPStore(store *auth.TOTPStore) error {
	if store == nil {
		return errors.New("TOTP state store is unavailable")
	}
	s.totpStore = store
	return nil
}

// ConfigureBuildInfo sets the package version and source revision shown in the
// authenticated administration dashboard.
func (s *Server) ConfigureBuildInfo(version, buildNumber string) {
	if version != "" {
		s.version = version
	}
	if buildNumber != "" {
		s.buildNumber = buildNumber
	}
}

// ConfigureStatistics attaches the private metrics feed to authenticated admin pages.
func (s *Server) ConfigureStatistics(feed *monitoring.Feed) error {
	if feed == nil {
		return errors.New("statistics feed is unavailable")
	}
	s.statistics = feed
	s.invalidateComponentHealth()
	return nil
}

// ConfigureSecurityEventWriter enables durable, signed administrator login
// events. Trusted proxies are explicit network ranges on the private admin
// ingress network; all other requests use their direct socket peer address.
func (s *Server) ConfigureSecurityEventWriter(directory string, key []byte, trustedProxyCIDRs []string) error {
	if strings.TrimSpace(directory) == "" || len(key) < 32 {
		return errors.New("security event directory and a 256-bit event key are required")
	}
	networks := make([]netip.Prefix, 0, len(trustedProxyCIDRs))
	for _, raw := range trustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid trusted proxy network %q", raw)
		}
		networks = append(networks, prefix.Masked())
	}
	s.securityEventDir = directory
	s.securityEventKey = append([]byte(nil), key...)
	s.trustedProxyNetworks = networks
	s.securityEventHealthy.Store(true)
	return nil
}

// SecurityEventWriterHealthy reports whether the last authentication event was
// durably appended and the writer was configured successfully.
func (s *Server) SecurityEventWriterHealthy() bool {
	return s.securityEventHealthy.Load()
}

// ConfigureSecurityControl connects the admin backend to the private security
// daemon. Its Unix socket is mounted only into the admin service.
func (s *Server) ConfigureSecurityControl(socket string) error {
	client, err := security.NewClient(socket)
	if err != nil {
		return err
	}
	s.securityControl = client
	return nil
}

const clientIPHeader = "X-JP-Client-IP"

func (s *Server) clientIP(r *http.Request) (string, error) {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	address, err := netip.ParseAddr(strings.TrimSpace(peer))
	if err != nil || address.Zone() != "" {
		return "", errors.New("request socket peer is not a valid IP address")
	}
	address = address.Unmap()
	for _, trusted := range s.trustedProxyNetworks {
		if trusted.Contains(address) {
			client, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(clientIPHeader)))
			if err != nil || client.Zone() != "" || client.IsUnspecified() || client.IsMulticast() {
				return "", errors.New("trusted proxy did not provide a valid client IP")
			}
			return client.Unmap().String(), nil
		}
	}
	if address.IsUnspecified() || address.IsMulticast() {
		return "", errors.New("request socket peer is not a unicast address")
	}
	return address.String(), nil
}

func (s *Server) recordAdminAuthEvent(r *http.Request, kind security.EventKind) {
	if len(s.securityEventKey) < 32 || s.securityEventDir == "" {
		s.securityEventHealthy.Store(false)
		return
	}
	ip, err := s.clientIP(r)
	if err != nil {
		s.securityEventHealthy.Store(false)
		s.logger.Error("identify administrator authentication source", "error", err)
		return
	}
	event, err := security.NewEvent(security.Admin, kind, ip, s.now().UTC())
	if err == nil {
		_, err = security.AppendEvent(s.securityEventDir, event, s.securityEventKey)
	}
	if err != nil {
		s.securityEventHealthy.Store(false)
		s.logger.Error("persist administrator authentication event", "error", err)
		return
	}
	s.securityEventHealthy.Store(true)
}

// ConfigureComponentHealth connects private service checks to the Overview.
// The WireGuard heartbeat is written by its existing container entrypoint and
// mounted read-only into admin; no Docker socket or public health endpoint is used.
func (s *Server) ConfigureComponentHealth(caddy interface{ CheckHealth() error }, wireguardHeartbeatPath string) {
	s.caddyHealth = caddy
	s.wireguardHealthPath = wireguardHeartbeatPath
	s.invalidateComponentHealth()
}

// ConfigureContainerHealth connects the private HTTP observer used in isolated integration environments.
func (s *Server) ConfigureContainerHealth(origin string) {
	s.containerHealth = containerhealth.NewClient(origin)
	s.invalidateComponentHealth()
}

// ConfigureContainerHealthSocket uses the host's restricted maintenance API.
// The admin service never receives a Docker API socket or network endpoint.
func (s *Server) ConfigureContainerHealthSocket(path string) {
	s.containerHealth = containerhealth.NewUnixClient(path)
	s.invalidateComponentHealth()
}

// ConfigureSystemMaintenanceSocket connects the authenticated dashboard to
// the restricted host observer and fixed backup/release maintenance workflows.
// The web process receives no host filesystem mount or Docker socket.
func (s *Server) ConfigureSystemMaintenanceSocket(path string) error {
	client, err := maintenance.NewUnixClient(path)
	if err != nil {
		return err
	}
	s.systemMaintenance = client
	return nil
}

// ConfigurePackageUploads sets the dedicated private staging directory shared
// through the persistent admin data volume with the host maintenance service.
func (s *Server) ConfigurePackageUploads(directory string) error {
	store, err := NewPackageUploadStore(directory)
	if err != nil {
		return err
	}
	s.packageUploads = store
	return nil
}

// StartPackageUploadCleanup periodically removes stale resumable packages and
// reports store failures through the configured admin logger.
func (s *Server) StartPackageUploadCleanup(ctx context.Context) {
	if s.packageUploads == nil {
		return
	}
	s.packageUploads.StartCleanup(ctx, time.Hour, func(err error) {
		s.logger.Error("clean expired release package uploads", "error", err)
	})
}

func (s *Server) confirmTOTPEnrollment(code string, at time.Time) error {
	if s.totpStore == nil {
		return errors.New("TOTP state store is unavailable")
	}
	s.authTransitionMu.Lock()
	defer s.authTransitionMu.Unlock()
	if err := s.totpStore.ConfirmEnrollment(code, at); err != nil {
		return err
	}
	s.sessions.RevokeAll()
	return nil
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, authenticated := s.session(r); authenticated {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	if _, ok := s.enrollmentOnlySession(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	id, csrf, err := s.sessions.Create(false)
	if err != nil {
		http.Error(w, "Unable to start a session", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, id, int(auth.DefaultSessionLifetime.Seconds()))
	data := map[string]any{"CSRF": csrf, "PasswordChanged": r.URL.Query().Get("password") == "changed"}
	data["TOTPDisabled"] = r.URL.Query().Get("totp") == "disabled" && s.totpStore != nil && s.totpStore.Status() == auth.TOTPUnconfigured
	if s.totpStore != nil && s.totpStore.Status() == auth.TOTPEnabled {
		data["TOTPRequired"] = true
	}
	if s.totpStore != nil && s.totpStore.RequiresEnrollment() {
		data["TOTPEnrollmentRequired"] = true
	}
	s.render(w, "login.html", data)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	oldID, _ := s.session(r)
	if !s.sessions.CheckCSRF(oldID, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if allowed, wait := s.limiter.Allow(); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+0.999)))
		http.Error(w, "Too many login attempts. Try again shortly.", http.StatusTooManyRequests)
		return
	}
	s.authTransitionMu.Lock()
	defer s.authTransitionMu.Unlock()
	requireTOTP := s.totpStore != nil && s.totpStore.Status() == auth.TOTPEnabled
	requireEnrollment := s.totpStore != nil && s.totpStore.RequiresEnrollment()
	if !s.credential.Verify(r.FormValue("password")) {
		s.limiter.Failed()
		s.recordAdminAuthEvent(r, security.LoginFailure)
		csrf, _, _ := s.sessions.State(oldID)
		message := "The password was not accepted."
		if requireTOTP {
			message = "The password or authenticator code was not accepted."
		}
		s.renderStatus(w, http.StatusUnauthorized, "login.html", map[string]any{"CSRF": csrf, "Error": message, "TOTPRequired": requireTOTP, "TOTPEnrollmentRequired": requireEnrollment})
		return
	}
	if requireTOTP {
		accepted, err := s.totpStore.Verify(r.FormValue("code"), s.now())
		if err != nil {
			s.logger.Error("verify administrator TOTP code", "error", err)
		}
		if err != nil || !accepted {
			s.limiter.Failed()
			s.recordAdminAuthEvent(r, security.LoginFailure)
			csrf, _, _ := s.sessions.State(oldID)
			s.renderStatus(w, http.StatusUnauthorized, "login.html", map[string]any{"CSRF": csrf, "Error": "The password or authenticator code was not accepted.", "TOTPRequired": true})
			return
		}
	}
	s.recordAdminAuthEvent(r, security.LoginSuccess)
	if requireEnrollment {
		if s.totpStore.Status() == auth.TOTPRecovery {
			secret, err := s.totpStore.BeginEnrollment()
			if err != nil {
				s.limiter.Failed()
				csrf, _, _ := s.sessions.State(oldID)
				s.renderStatus(w, http.StatusServiceUnavailable, "login.html", map[string]any{"CSRF": csrf, "Error": "Authenticator setup could not be started.", "TOTPEnrollmentRequired": true})
				return
			}
			clear(secret)
		}
		if oldID != "" {
			s.sessions.Revoke(oldID)
		}
		id, _, err := s.sessions.CreateEnrollmentOnly()
		if err != nil {
			s.limiter.Failed()
			http.Error(w, "Unable to start a session", http.StatusInternalServerError)
			return
		}
		if !s.sessions.GrantRecentPasswordVerification(id, totpReauthenticationLifetime) {
			s.sessions.Revoke(id)
			http.Error(w, "Unable to start authenticator setup", http.StatusInternalServerError)
			return
		}
		s.limiter.Succeeded()
		s.setCookie(w, id, int(auth.DefaultSessionLifetime.Seconds()))
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.limiter.Succeeded()
	if oldID != "" {
		s.sessions.Revoke(oldID)
	}
	id, _, err := s.sessions.Create(true)
	if err != nil {
		http.Error(w, "Unable to start a session", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, id, int(auth.DefaultSessionLifetime.Seconds()))
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	id, _ := s.session(r)
	if !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	s.sessions.Revoke(id)
	s.setCookie(w, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	id, authenticated := s.session(r)
	if !authenticated {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if s.credentialPath == "" {
		http.Error(w, "Password changes are unavailable", http.StatusServiceUnavailable)
		return
	}
	if allowed, wait := s.passwordLimiter.Allow(); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+0.999)))
		http.Error(w, "Too many password change attempts. Try again shortly.", http.StatusTooManyRequests)
		return
	}
	current, replacement, confirmation := r.FormValue("current_password"), r.FormValue("new_password"), r.FormValue("confirm_password")
	if !s.credential.Verify(current) {
		s.passwordLimiter.Failed()
		http.Error(w, "The current password was not accepted.", http.StatusUnauthorized)
		return
	}
	if replacement != confirmation {
		s.passwordLimiter.Failed()
		http.Error(w, "The new password confirmation does not match.", http.StatusBadRequest)
		return
	}
	if s.credential.Verify(replacement) {
		s.passwordLimiter.Failed()
		http.Error(w, "Choose a password different from the current password.", http.StatusBadRequest)
		return
	}
	s.authTransitionMu.Lock()
	defer s.authTransitionMu.Unlock()
	if !s.credential.Verify(current) {
		s.passwordLimiter.Failed()
		http.Error(w, "The current password was not accepted.", http.StatusUnauthorized)
		return
	}
	if s.totpStore != nil && s.totpStore.Status() == auth.TOTPEnabled {
		accepted, err := s.totpStore.Verify(r.FormValue("code"), s.now())
		if err != nil || !accepted {
			s.passwordLimiter.Failed()
			if err != nil {
				s.logger.Error("verify administrator TOTP code before changing password", "error", err)
			}
			http.Error(w, "The password or authenticator code was not accepted.", http.StatusUnauthorized)
			return
		}
	}
	if err := s.credential.ReplacePassword(s.credentialPath, replacement); err != nil {
		s.passwordLimiter.Failed()
		http.Error(w, "The new password could not be saved. Check that it meets the password policy.", http.StatusBadRequest)
		return
	}
	s.passwordLimiter.Succeeded()
	s.sessions.RevokeAll()
	s.setCookie(w, "", -1)
	http.Redirect(w, r, "/?password=changed", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	s.adminPage(w, r, "overview")
}

func (s *Server) accessControlPage(w http.ResponseWriter, r *http.Request) {
	s.adminPage(w, r, "access-control")
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request) {
	s.adminPage(w, r, "security")
}

func (s *Server) wireGuardPage(w http.ResponseWriter, r *http.Request) {
	s.adminPage(w, r, "wireguard")
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request, page string) {
	id, authenticated := s.session(r)
	if !authenticated {
		if enrollmentID, ok := s.enrollmentOnlySession(r); ok {
			if page == "overview" {
				s.recoveryEnrollmentPage(w, enrollmentID)
			} else {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if s.adminAppIndex(w) {
		return
	}
	csrf, _, _ := s.sessions.State(id)
	entries := []string{}
	namedEntries := []whitelist.Entry{}
	if s.whitelist != nil {
		var err error
		namedEntries, err = s.whitelist.ListEntries()
		if err != nil {
			http.Error(w, "Whitelist is unavailable", http.StatusServiceUnavailable)
			return
		}
		entries = whitelist.Addresses(namedEntries)
		if entries == nil {
			entries = []string{}
		}
		if namedEntries == nil {
			namedEntries = []whitelist.Entry{}
		}
	}
	titles := map[string][3]string{
		"overview":       {"Overview", "JELLYFIN PROXY", "Component health and deployment information."},
		"access-control": {"Access control", "ACCESS", "Manage the addresses allowed to reach Jellyfin."},
		"security":       {"Security", "ACCOUNT SECURITY", "Manage administrator two-factor authentication."},
		"wireguard":      {"WireGuard", "TUNNEL", "Download the retained peer configuration for the official WireGuard client."},
	}
	pageDetails := titles[page]
	data := map[string]any{
		"CSRF": csrf, "Entries": entries, "NamedEntries": namedEntries, "WhitelistEnabled": s.whitelist != nil,
		"WireGuardEnabled": s.wireguardClientConfig != "", "TOTPConfigured": s.totpStore != nil,
		"CredentialChangeEnabled": s.credentialPath != "",
		"Version":                 s.version, "BuildNumber": s.buildNumber, "Page": page,
		"Title": pageDetails[0], "Eyebrow": pageDetails[1], "Description": pageDetails[2],
	}
	if s.totpStore != nil {
		status := s.totpStore.Status()
		data["TOTPStatus"] = status
		data["TOTPConfigured"] = true
		if status == auth.TOTPPending && s.sessions.HasRecentPasswordVerification(id) {
			secret, err := s.totpStore.PendingSecret()
			if err != nil {
				s.logger.Error("read pending administrator TOTP setup", "error", err)
				http.Error(w, "Authenticator setup is unavailable", http.StatusServiceUnavailable)
				return
			}
			defer clear(secret)
			uri := totpProvisioningURI(secret)
			encodedQR, err := qrcode.Encode(uri, qrcode.Medium, 256)
			if err != nil {
				s.logger.Error("generate administrator TOTP QR code")
				http.Error(w, "Authenticator setup is unavailable", http.StatusInternalServerError)
				return
			}
			data["TOTPSecret"] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
			data["TOTPQRCode"] = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(encodedQR))
			data["TOTPSetupVisible"] = true
		}
	}
	if page == "overview" {
		data["Components"] = s.componentHealth(entries)
	}
	templates := map[string]string{
		"overview": "dashboard.html", "access-control": "access_control.html",
		"security": "security.html", "wireguard": "wireguard.html",
	}
	s.render(w, templates[page], data)
}

type componentStatus struct {
	Name          string     `json:"name"`
	State         string     `json:"state"`
	Class         string     `json:"class"`
	Detail        string     `json:"detail"`
	CheckedAt     time.Time  `json:"checked_at"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
}

func (s *Server) healthPage(w http.ResponseWriter, r *http.Request) {
	s.adminPage(w, r, "health")
}

func (s *Server) apiInitial(w http.ResponseWriter, r *http.Request) {
	id, authenticated := s.session(r)
	if !authenticated {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	csrf, _, ok := s.sessions.State(id)
	if !ok {
		http.Error(w, "Administrator session expired", http.StatusUnauthorized)
		return
	}
	entries := []string{}
	namedEntries := []whitelist.Entry{}
	if s.whitelist != nil {
		var err error
		namedEntries, err = s.whitelist.ListEntries()
		if err != nil {
			http.Error(w, "Whitelist is unavailable", http.StatusServiceUnavailable)
			return
		}
		entries = whitelist.Addresses(namedEntries)
		if entries == nil {
			entries = []string{}
		}
		if namedEntries == nil {
			namedEntries = []whitelist.Entry{}
		}
	}
	status := auth.TOTPUnconfigured
	if s.totpStore != nil {
		status = s.totpStore.Status()
	}
	var wireguardStatus *wireguard.PeerStatus
	if s.wireguardControl.SocketPath != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		status, err := s.wireguardControl.Status(ctx)
		cancel()
		if err == nil {
			wireguardStatus = &status
		}
	}
	configAvailable := s.wireguardConfigAvailable()
	if wireguardStatus != nil {
		configAvailable = wireguardStatus.ConfigAvailable
	}
	result := map[string]any{
		"csrf": csrf, "version": s.version, "build_number": s.buildNumber,
		"whitelist_enabled": s.whitelist != nil, "whitelist": entries, "whitelist_entries": namedEntries,
		"wireguard_enabled": s.wireguardClientConfig != "", "wireguard_config_available": configAvailable, "totp_status": string(status),
		"components": s.cachedComponentHealth(entries, wireguardStatus), "health_events": s.recentHealthEvents(),
		"current": monitoring.LiveData{Status: "disconnected"},
	}
	if s.securityControl == nil {
		result["security_error"] = "Security monitoring is not configured."
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		securitySnapshot, securityErr := s.securityControl.Snapshot(ctx)
		cancel()
		if securityErr != nil {
			result["security_error"] = "Security monitoring is temporarily unavailable."
		} else {
			result["security"] = securitySnapshot
		}
	}
	if wireguardStatus != nil {
		result["wireguard_status"] = wireguardStatus
	}
	if s.statistics != nil {
		result["current"] = s.statistics.Current()
	}
	if status == auth.TOTPPending && s.sessions.HasRecentPasswordVerification(id) {
		secret, err := s.totpStore.PendingSecret()
		if err != nil {
			s.logger.Error("read pending administrator TOTP setup", "error", err)
			http.Error(w, "Authenticator setup is unavailable", http.StatusServiceUnavailable)
			return
		}
		uri := totpProvisioningURI(secret)
		qr, err := qrcode.Encode(uri, qrcode.Medium, 256)
		clear(secret)
		if err != nil {
			http.Error(w, "Authenticator setup is unavailable", http.StatusInternalServerError)
			return
		}
		secret, err = s.totpStore.PendingSecret()
		if err != nil {
			http.Error(w, "Authenticator setup is unavailable", http.StatusServiceUnavailable)
			return
		}
		result["totp_setup_visible"] = true
		result["totp_secret"] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
		result["totp_qr_code"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(qr)
		clear(secret)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		s.logger.Debug("write admin app bootstrap", "error", err)
	}
}

func (s *Server) wireguardConfigAvailable() bool {
	if s.wireguardClientConfig == "" {
		return false
	}
	_, err := wireguard.LoadRetainedClientConfig(s.wireguardClientConfig)
	return err == nil
}

func (s *Server) componentHealth(entries []string) []componentStatus {
	items, _ := s.componentHealthSnapshot(entries)
	return items
}

func (s *Server) componentHealthSnapshot(entries []string) ([]componentStatus, *wireguard.PeerStatus) {
	s.componentHealthMu.Lock()
	defer s.componentHealthMu.Unlock()
	now := s.now().UTC()
	if s.componentHealthCacheFresh(now) {
		return cloneComponentStatuses(s.componentHealthCache), s.componentHealthWireGuard
	}
	var status *wireguard.PeerStatus
	if s.wireguardControl.SocketPath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		observed, err := s.wireguardControl.Status(ctx)
		cancel()
		if err == nil {
			status = &observed
		}
	}
	return s.observeAndCacheComponentHealth(now, entries, status), status
}

func (s *Server) cachedComponentHealth(entries []string, wireguardStatus *wireguard.PeerStatus) []componentStatus {
	s.componentHealthMu.Lock()
	defer s.componentHealthMu.Unlock()
	now := s.now().UTC()
	if s.componentHealthCacheFresh(now) {
		return cloneComponentStatuses(s.componentHealthCache)
	}
	return s.observeAndCacheComponentHealth(now, entries, wireguardStatus)
}

func (s *Server) componentHealthCacheFresh(now time.Time) bool {
	if len(s.componentHealthCache) == 0 {
		return false
	}
	age := now.Sub(s.componentHealthAt)
	return age >= 0 && age < 15*time.Second
}

func (s *Server) observeAndCacheComponentHealth(now time.Time, entries []string, wireguardStatus *wireguard.PeerStatus) []componentStatus {
	items := s.observeComponentHealth(entries, wireguardStatus)
	s.componentHealthAt = now
	s.componentHealthCache = cloneComponentStatuses(items)
	s.componentHealthWireGuard = wireguardStatus
	return items
}

func (s *Server) invalidateComponentHealth() {
	s.componentHealthMu.Lock()
	s.componentHealthAt = time.Time{}
	s.componentHealthCache = nil
	s.componentHealthWireGuard = nil
	s.componentHealthMu.Unlock()
}

func (s *Server) initializeCPUPressure() {
	if s.cpuPressure.initialized {
		return
	}
	s.healthMu.Lock()
	previous := s.healthRecords["Host metrics"]
	s.healthMu.Unlock()
	s.cpuPressure.Initialize(previous.State == "Degraded")
}

func cloneComponentStatuses(items []componentStatus) []componentStatus {
	return append([]componentStatus(nil), items...)
}

func (s *Server) observeComponentHealth(entries []string, wireguardStatus *wireguard.PeerStatus) []componentStatus {
	now := s.now().UTC()
	result := []componentStatus{}
	add := func(name, state, detail string) {
		item := componentStatus{Name: name, State: state, Class: strings.ToLower(state), Detail: detail, CheckedAt: now}
		result = append(result, item)
	}
	add("Admin backend", "Healthy", "This authenticated request reached the admin handler.")
	if s.whitelist == nil {
		add("Access control", "Unknown", "Whitelist management is not configured, so its active policy cannot be inspected.")
	} else {
		add("Access control", "Healthy", fmt.Sprintf("The active allowlist is available (%d entries).", len(entries)))
	}
	if s.caddyHealth == nil {
		add("Caddy / proxy", "Unknown", "The private Caddy health check is not configured.")
	} else if err := s.caddyHealth.CheckHealth(); err != nil {
		add("Caddy / proxy", "Down", "The private Caddy health check failed: "+err.Error())
	} else {
		add("Caddy / proxy", "Healthy", "Caddy responded through its private admin socket.")
	}
	if s.wireguardHeartbeatHealthy() {
		add("WireGuard interface", "Healthy", "A recent heartbeat confirms that the interface is up. This does not prove peer reachability.")
	} else {
		add("WireGuard interface", "Unknown", "No fresh interface heartbeat is available; the cause cannot be distinguished from this read-only check.")
	}
	if s.wireguardControl.SocketPath == "" {
		add("Windows peer", "Unknown", "The private WireGuard status socket is not configured.")
		add("Jellyfin endpoint", "Unknown", "The private WireGuard status socket is not configured.")
	} else if wireguardStatus == nil {
		add("Windows peer", "Unknown", "The private WireGuard status check is unavailable.")
		add("Jellyfin endpoint", "Unknown", "The private Jellyfin reachability check is unavailable.")
	} else {
		peerState := wireguardStatus.PeerState
		if peerState != "Healthy" && peerState != "Degraded" && peerState != "Down" {
			peerState = "Unknown"
		}
		jellyfinState := wireguardStatus.JellyfinState
		if jellyfinState != "Healthy" && jellyfinState != "Down" {
			jellyfinState = "Unknown"
		}
		add("Windows peer", peerState, wireguardStatus.PeerDetail)
		add("Jellyfin endpoint", jellyfinState, wireguardStatus.JellyfinDetail)
	}
	current := monitoring.LiveData{}
	if s.statistics != nil {
		current = s.statistics.Current()
	}
	if current.Host == nil {
		add("Host metrics", "Unknown", "The host collector has not supplied a fresh sample.")
	} else {
		state, detail := "Healthy", "A fresh host collector sample is available."
		cpuState, cpuDetail := state, detail
		if current.Host.CPUPercent != nil {
			s.initializeCPUPressure()
			degraded, phase := s.cpuPressure.Observe(*current.Host.CPUPercent)
			switch phase {
			case "confirming":
				cpuDetail = fmt.Sprintf("CPU is %.1f%%; another high sample is required before marking sustained pressure.", *current.Host.CPUPercent)
			case "recovering":
				cpuState, cpuDetail = "Degraded", fmt.Sprintf("CPU has fallen to %.1f%%; another low sample is required to confirm recovery.", *current.Host.CPUPercent)
			case "degraded":
				cpuState, cpuDetail = "Degraded", fmt.Sprintf("Sustained CPU usage is %.1f%%; recovery requires two samples at or below 85%%.", *current.Host.CPUPercent)
			case "recovered":
				cpuDetail = "CPU pressure cleared after two fresh samples at or below 85%."
			}
			if degraded {
				cpuState = "Degraded"
			}
		}
		if current.Host.DiskUsedBytes != nil && current.Host.DiskTotalBytes != nil && *current.Host.DiskTotalBytes > 0 && float64(*current.Host.DiskUsedBytes)/float64(*current.Host.DiskTotalBytes) >= 0.9 {
			state, detail = "Degraded", "Disk usage is at least 90% of measured capacity."
		} else if current.Host.MemoryUsedBytes != nil && current.Host.MemoryTotalBytes != nil && *current.Host.MemoryTotalBytes > 0 && float64(*current.Host.MemoryUsedBytes)/float64(*current.Host.MemoryTotalBytes) >= 0.9 {
			state, detail = "Degraded", "Memory usage is at least 90% of measured capacity."
		} else {
			state, detail = cpuState, cpuDetail
		}
		add("Host metrics", state, detail)
	}
	if current.Proxy == nil {
		add("Proxy metrics", "Unknown", "A fresh Caddy traffic metrics sample is not available.")
	} else {
		state, detail := "Healthy", "A fresh Caddy traffic metrics sample is available."
		if current.Proxy.ErrorRatePercent != nil && *current.Proxy.ErrorRatePercent >= 5 {
			state, detail = "Degraded", fmt.Sprintf("The latest measured HTTP error rate is %.1f%%.", *current.Proxy.ErrorRatePercent)
		}
		add("Proxy metrics", state, detail)
	}
	s.addContainerHealth(add)
	return s.recordHealth(result, now)
}

func (s *Server) addContainerHealth(add func(string, string, string)) {
	services := []struct{ name, service string }{
		{"Admin container", "admin"},
		{"Host metrics container", "hostmetrics"},
		{"Caddy container", "caddy"},
		{"WireGuard container", "wireguard"},
	}
	if s.containerHealth == nil {
		for _, item := range services {
			add(item.name, "Unknown", "The private Docker health observer is not configured.")
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	snapshots, err := s.containerHealth.Snapshot(ctx)
	if err != nil {
		for _, item := range services {
			add(item.name, "Unknown", "The private Docker health observer could not provide a fresh status.")
		}
		return
	}
	byService := make(map[string]containerhealth.Snapshot, len(snapshots))
	for _, snapshot := range snapshots {
		byService[snapshot.Service] = snapshot
	}
	for _, item := range services {
		snapshot, ok := byService[item.service]
		if !ok {
			add(item.name, "Unknown", "No managed container was returned for this service.")
			continue
		}
		state := "Unknown"
		switch {
		case snapshot.State == "running" && snapshot.Health == "healthy":
			state = "Healthy"
		case snapshot.State == "running" && snapshot.Health == "unhealthy":
			state = "Down"
		case snapshot.State == "exited" || snapshot.State == "dead":
			state = "Down"
		case snapshot.State == "running" && snapshot.Health == "starting":
			state = "Degraded"
		case snapshot.State == "restarting" || snapshot.State == "paused" || snapshot.State == "created":
			state = "Degraded"
		}
		detail := fmt.Sprintf("Docker state %s · health %s · %d restarts", snapshot.State, snapshot.Health, snapshot.RestartCount)
		if !snapshot.StartedAt.IsZero() {
			detail += " · started " + snapshot.StartedAt.UTC().Format(time.RFC3339)
		}
		add(item.name, state, detail)
	}
}

func (s *Server) wireguardHeartbeatHealthy() bool {
	if s.wireguardHealthPath == "" {
		return false
	}
	data, err := os.ReadFile(s.wireguardHealthPath)
	if err != nil {
		return false
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return false
	}
	age := s.now().Sub(time.Unix(seconds, 0))
	return age >= -5*time.Second && age <= 15*time.Second
}

func (s *Server) statisticsPage(w http.ResponseWriter, r *http.Request) {
	id, authenticated := s.session(r)
	if !authenticated {
		if _, recovery := s.enrollmentOnlySession(r); recovery {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if s.adminAppIndex(w) {
		return
	}
	status := "Waiting for live metrics"
	csrf, _, _ := s.sessions.State(id)
	if s.statistics != nil {
		switch s.statistics.Current().Status {
		case "live":
			status = "Live"
		case "partial":
			status = "Partially available"
		case "disconnected":
			status = "Reconnecting"
		}
	}
	data := map[string]any{
		"CSRF": csrf,
		"Page": "statistics", "Title": "Statistics", "Eyebrow": "MONITORING", "Description": "Live VPS and Jellyfin proxy measurements.",
		"MonitoringStatus": status,
		"WhitelistEnabled": s.whitelist != nil,
		"WireGuardEnabled": s.wireguardClientConfig != "",
		"TOTPConfigured":   s.totpStore != nil,
	}
	if s.totpStore != nil {
		data["TOTPStatus"] = s.totpStore.Status()
	}
	s.render(w, "statistics.html", data)
}

func (s *Server) statisticsEvents(w http.ResponseWriter, r *http.Request) {
	id, authenticated := s.session(r)
	if !authenticated {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	if s.statistics == nil {
		http.Error(w, "Statistics are unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "Live statistics are unavailable", http.StatusInternalServerError)
		return
	}
	subscription, events, err := s.statistics.Subscribe()
	if err != nil {
		http.Error(w, "Live statistics are at capacity", http.StatusServiceUnavailable)
		return
	}
	defer s.statistics.Unsubscribe(subscription)
	var securityUpdates <-chan security.Snapshot
	if s.securityControl != nil {
		updates, subscribeErr := s.securityControl.Subscribe(r.Context())
		if subscribeErr != nil {
			s.logger.Warn("subscribe to live security events", "error", subscribeErr)
		} else {
			securityUpdates = updates
		}
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil {
		s.logger.Debug("clear admin response deadline for statistics stream", "error", err)
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher := w.(http.Flusher)
	_, _ = io.WriteString(w, "retry: 2000\n\n")
	flusher.Flush()

	write := func(current monitoring.LiveData) bool {
		payload, err := json.Marshal(current)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: metrics\ndata: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	writeHealth := func() bool {
		entries := []string{}
		if s.whitelist != nil {
			var err error
			entries, err = s.whitelist.List()
			if err != nil {
				s.logger.Error("read allowlist for health event", "error", err)
				return true
			}
		}
		components, wireguardStatus := s.componentHealthSnapshot(entries)
		payloadData := map[string]any{"components": components, "health_events": s.recentHealthEvents()}
		if wireguardStatus != nil {
			payloadData["wireguard_status"] = wireguardStatus
		}
		payload, err := json.Marshal(payloadData)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: health\ndata: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	writeSecurity := func(snapshot security.Snapshot) bool {
		payload, err := json.Marshal(snapshot)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: security\ndata: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	writeAuthenticationRequired := func() {
		_, _ = io.WriteString(w, "event: auth-required\ndata: {}\n\n")
		flusher.Flush()
	}
	if !write(s.statistics.Current()) {
		return
	}
	if !writeHealth() {
		return
	}
	if s.securityControl != nil && securityUpdates == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		current, snapshotErr := s.securityControl.Snapshot(ctx)
		cancel()
		if snapshotErr == nil && !writeSecurity(current) {
			return
		}
	}
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case current, ok := <-events:
			_, stillAuthenticated, sessionValid := s.sessions.State(id)
			if !sessionValid || !stillAuthenticated {
				writeAuthenticationRequired()
				return
			}
			if !ok || !write(current) {
				return
			}
		case snapshot, ok := <-securityUpdates:
			_, stillAuthenticated, sessionValid := s.sessions.State(id)
			if !sessionValid || !stillAuthenticated {
				writeAuthenticationRequired()
				return
			}
			if !ok || !writeSecurity(snapshot) {
				return
			}
		case <-keepalive.C:
			_, stillAuthenticated, sessionValid := s.sessions.State(id)
			if !sessionValid || !stillAuthenticated {
				writeAuthenticationRequired()
				return
			}
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			if !writeHealth() {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) statisticsHistory(w http.ResponseWriter, r *http.Request) {
	if _, authenticated := s.session(r); !authenticated {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	if s.statistics == nil {
		http.Error(w, "Statistics are unavailable", http.StatusServiceUnavailable)
		return
	}
	points, ok := s.statistics.HistoryRange(r.URL.Query().Get("range"), s.now().UTC())
	if !ok {
		http.Error(w, "Unsupported statistics range", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(points); err != nil {
		s.logger.Error("encode statistics history response", "error", err)
	}
}

type statisticsSettingsResponse struct {
	ProxyRetentionDays    int    `json:"proxy_retention_days"`
	SecurityRetentionDays int    `json:"security_retention_days"`
	DatabaseBytes         int64  `json:"database_bytes"`
	RetainedSamples       int64  `json:"retained_samples"`
	DiskAvailableBytes    uint64 `json:"disk_available_bytes,omitempty"`
}

func (s *Server) statisticsSettings(w http.ResponseWriter, r *http.Request) {
	if _, authenticated := s.session(r); !authenticated {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	if s.statistics == nil || s.securityControl == nil {
		http.Error(w, "Statistics settings are unavailable", http.StatusServiceUnavailable)
		return
	}
	proxyDays, databaseBytes, samples, err := s.statistics.StorageSettings()
	if err != nil {
		http.Error(w, "Statistics storage details are unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	securitySnapshot, err := s.securityControl.Snapshot(ctx)
	if err != nil {
		http.Error(w, "Security retention settings are unavailable", http.StatusServiceUnavailable)
		return
	}
	response := statisticsSettingsResponse{ProxyRetentionDays: proxyDays, SecurityRetentionDays: int(securitySnapshot.Config.HistoryRetention / (24 * time.Hour)), DatabaseBytes: databaseBytes, RetainedSamples: samples}
	if host := s.statistics.Current().Host; host != nil && host.DiskTotalBytes != nil && host.DiskUsedBytes != nil && *host.DiskTotalBytes >= *host.DiskUsedBytes {
		response.DiskAvailableBytes = *host.DiskTotalBytes - *host.DiskUsedBytes
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) updateStatisticsSettings(w http.ResponseWriter, r *http.Request) {
	id, authenticated := s.session(r)
	if !authenticated {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	if !s.sessions.CheckCSRF(id, r.Header.Get("X-CSRF-Token")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if s.statistics == nil || s.securityControl == nil {
		http.Error(w, "Statistics settings are unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var requested struct {
		ProxyRetentionDays    int `json:"proxy_retention_days"`
		SecurityRetentionDays int `json:"security_retention_days"`
	}
	if err := decoder.Decode(&requested); err != nil || requireAdminJSONEOF(decoder) != nil || !allowedRetentionDays(requested.ProxyRetentionDays) || !allowedRetentionDays(requested.SecurityRetentionDays) {
		http.Error(w, "Retention must be 7, 14, 30, 60, 90, or 180 days", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	before, err := s.securityControl.Snapshot(ctx)
	if err != nil {
		http.Error(w, "Security settings could not be read", http.StatusServiceUnavailable)
		return
	}
	config := before.Config
	config.HistoryRetention = time.Duration(requested.SecurityRetentionDays) * 24 * time.Hour
	if _, err := s.securityControl.UpdateConfig(ctx, config); err != nil {
		http.Error(w, "Security retention could not be saved", http.StatusConflict)
		return
	}
	if err := s.statistics.SetRetentionDays(requested.ProxyRetentionDays); err != nil {
		if _, rollbackErr := s.securityControl.UpdateConfig(ctx, before.Config); rollbackErr != nil {
			s.logger.Error("rollback security retention after statistics save failed", "error", rollbackErr)
		}
		http.Error(w, "Proxy retention could not be saved", http.StatusConflict)
		return
	}
	s.statisticsSettings(w, r)
}

func allowedRetentionDays(days int) bool {
	switch days {
	case 7, 14, 30, 60, 90, 180:
		return true
	default:
		return false
	}
}

func (s *Server) securityHistory(w http.ResponseWriter, r *http.Request) {
	if _, authenticated := s.session(r); !authenticated {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	if s.securityControl == nil {
		http.Error(w, "Security monitoring is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := s.securityControl.History(ctx, r.URL.Query().Get("range"), r.URL.Query().Get("service"), r.URL.Query().Get("q"))
	if err != nil {
		http.Error(w, "Security history is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(rows)
}

func (s *Server) securityMutationSession(w http.ResponseWriter, r *http.Request) bool {
	id, authenticated := s.session(r)
	if !authenticated {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return false
	}
	if !s.sessions.CheckCSRF(id, r.Header.Get("X-CSRF-Token")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return false
	}
	if s.securityControl == nil {
		http.Error(w, "Security management is unavailable", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (s *Server) updateSecurityConfig(w http.ResponseWriter, r *http.Request) {
	if !s.securityMutationSession(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var config security.Config
	if err := decoder.Decode(&config); err != nil {
		http.Error(w, "Invalid security configuration", http.StatusBadRequest)
		return
	}
	if err := requireAdminJSONEOF(decoder); err != nil {
		http.Error(w, "Invalid security configuration", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	snapshot, err := s.securityControl.UpdateConfig(ctx, config)
	if err != nil {
		http.Error(w, "Security configuration could not be applied. Check the values and protection health.", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(snapshot)
}

func (s *Server) unbanSecurityIP(w http.ResponseWriter, r *http.Request) {
	if !s.securityMutationSession(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request struct {
		Service security.Service `json:"service"`
		IP      string           `json:"ip"`
	}
	if err := decoder.Decode(&request); err != nil || requireAdminJSONEOF(decoder) != nil {
		http.Error(w, "Invalid unban request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	snapshot, err := s.securityControl.Unban(ctx, request.Service, request.IP)
	if err != nil {
		http.Error(w, "The address could not be unbanned. Refresh the security status and retry.", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(snapshot)
}

func requireAdminJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON data")
		}
		return err
	}
	return nil
}

func (s *Server) disableTOTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	id, authenticated := s.session(r)
	if !authenticated {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if s.totpStore == nil {
		http.Error(w, "Authenticator management is unavailable", http.StatusServiceUnavailable)
		return
	}
	if allowed, wait := s.limiter.Allow(); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+0.999)))
		http.Error(w, "Too many verification attempts. Try again shortly.", http.StatusTooManyRequests)
		return
	}

	s.authTransitionMu.Lock()
	defer s.authTransitionMu.Unlock()
	if _, stillAuthenticated := s.session(r); !stillAuthenticated || !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Session expired; sign in again", http.StatusForbidden)
		return
	}
	if s.totpStore.Status() != auth.TOTPEnabled {
		http.Error(w, "Authenticator is not enabled", http.StatusConflict)
		return
	}
	if !s.credential.Verify(r.FormValue("password")) {
		s.limiter.Failed()
		http.Error(w, "The password or authenticator code was not accepted.", http.StatusUnauthorized)
		return
	}
	accepted, err := s.totpStore.Verify(r.FormValue("code"), s.now())
	if err != nil || !accepted {
		s.limiter.Failed()
		if err != nil {
			s.logger.Error("verify administrator TOTP code before disabling", "error", err)
		}
		http.Error(w, "The password or authenticator code was not accepted.", http.StatusUnauthorized)
		return
	}
	if err := s.totpStore.Disable(); err != nil {
		s.limiter.Failed()
		s.logger.Error("disable administrator TOTP", "error", err)
		http.Error(w, "Authenticator could not be disabled", http.StatusServiceUnavailable)
		return
	}
	s.limiter.Succeeded()
	s.sessions.RevokeAll()
	http.Redirect(w, r, "/?totp=disabled", http.StatusSeeOther)
}

func (s *Server) recoveryEnrollmentPage(w http.ResponseWriter, id string) {
	csrf, _, ok := s.sessions.State(id)
	if !ok || !s.sessions.EnrollmentOnly(id) || s.totpStore == nil || !s.totpStore.RequiresEnrollment() {
		http.Error(w, "Authenticator setup is unavailable", http.StatusForbidden)
		return
	}
	data := map[string]any{"CSRF": csrf}
	if s.totpStore.Status() == auth.TOTPPending && s.sessions.HasRecentPasswordVerification(id) {
		secret, err := s.totpStore.PendingSecret()
		if err != nil {
			s.logger.Error("read recovery TOTP setup state", "error", err)
			http.Error(w, "Authenticator setup is unavailable", http.StatusServiceUnavailable)
			return
		}
		defer clear(secret)
		encodedQR, err := qrcode.Encode(totpProvisioningURI(secret), qrcode.Medium, 256)
		if err != nil {
			s.logger.Error("generate recovery TOTP QR code")
			http.Error(w, "Authenticator setup is unavailable", http.StatusInternalServerError)
			return
		}
		data["TOTPSecret"] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
		data["TOTPQRCode"] = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(encodedQR))
		data["TOTPSetupVisible"] = true
	}
	s.render(w, "totp_recovery.html", data)
}

func (s *Server) startTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	id, authenticated := s.session(r)
	enrollmentOnly := s.sessions.EnrollmentOnly(id)
	if !authenticated && !enrollmentOnly {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if allowed, wait := s.limiter.Allow(); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+0.999)))
		http.Error(w, "Too many verification attempts. Try again shortly.", http.StatusTooManyRequests)
		return
	}
	if !s.credential.Verify(r.FormValue("password")) {
		s.limiter.Failed()
		http.Error(w, "The password was not accepted.", http.StatusUnauthorized)
		return
	}
	s.limiter.Succeeded()
	if s.totpStore == nil {
		http.Error(w, "Authenticator setup is unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.totpStore.Status() == auth.TOTPUnconfigured {
		secret, err := s.totpStore.BeginEnrollment()
		if err != nil {
			http.Error(w, "Authenticator setup could not be started", http.StatusConflict)
			return
		}
		clear(secret)
	}
	if s.totpStore.Status() != auth.TOTPPending {
		http.Error(w, "Authenticator setup is not available", http.StatusConflict)
		return
	}
	if !s.sessions.GrantRecentPasswordVerification(id, totpReauthenticationLifetime) {
		http.Error(w, "Session expired; sign in again", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

func (s *Server) confirmTOTPEnrollmentHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	id, authenticated := s.session(r)
	enrollmentOnly := s.sessions.EnrollmentOnly(id)
	if !authenticated && !enrollmentOnly {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if !s.sessions.HasRecentPasswordVerification(id) {
		http.Error(w, "Verify your administrator password before completing setup", http.StatusForbidden)
		return
	}
	if allowed, wait := s.limiter.Allow(); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+0.999)))
		http.Error(w, "Too many verification attempts. Try again shortly.", http.StatusTooManyRequests)
		return
	}
	s.limiter.Failed()
	if err := s.confirmTOTPEnrollment(r.FormValue("code"), s.now()); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, auth.ErrInvalidTOTPCode) {
			http.Error(w, "The authenticator code was not accepted.", status)
			return
		}
		if errors.Is(err, auth.ErrNoTOTPEnrollment) {
			status = http.StatusConflict
		}
		s.logger.Error("confirm administrator TOTP enrollment", "error", err)
		http.Error(w, "Authenticator setup could not be completed", status)
		return
	}
	s.limiter.Succeeded()
	s.setCookie(w, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) cancelTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	id, authenticated := s.session(r)
	enrollmentOnly := s.sessions.EnrollmentOnly(id)
	if !authenticated && !enrollmentOnly {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if s.totpStore == nil {
		http.Error(w, "Authenticator setup is unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.totpStore.CancelEnrollment(); err != nil {
		http.Error(w, "No incomplete authenticator setup is available", http.StatusConflict)
		return
	}
	s.sessions.Revoke(id)
	s.setCookie(w, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func totpProvisioningURI(secret []byte) string {
	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	label := "Jellyfin Proxy:Administrator"
	query := url.Values{}
	query.Set("secret", encodedSecret)
	query.Set("issuer", "Jellyfin Proxy")
	query.Set("algorithm", "SHA1")
	query.Set("digits", "6")
	query.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", url.PathEscape(label), query.Encode())
}

func (s *Server) downloadWireGuardConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	id, authenticated := s.session(r)
	if !authenticated {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if s.wireguardClientConfig == "" {
		http.Error(w, "Windows WireGuard configuration is unavailable", http.StatusServiceUnavailable)
		return
	}
	s.wireguardConfigMu.Lock()
	defer s.wireguardConfigMu.Unlock()
	data, err := wireguard.LoadRetainedClientConfig(s.wireguardClientConfig)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Error("load retained Windows WireGuard configuration", "error", err)
		}
		http.Error(w, "Windows WireGuard configuration is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="jellyfin-proxy.conf"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	written, writeErr := w.Write(data)
	clear(data)
	if writeErr != nil || written != len(data) {
		// Retain the configuration so an interrupted transfer can be retried.
		return
	}
	if err := os.Remove(s.wireguardClientConfig); err != nil {
		s.logger.Error("remove downloaded Windows WireGuard configuration", "error", err)
	}
}

func (s *Server) rotateWireGuardConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	id, authenticated := s.session(r)
	if !authenticated {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if s.wireguardClientConfig == "" || s.wireguardControl.SocketPath == "" || s.wireguardEndpoint == "" {
		http.Error(w, "WireGuard peer rotation is unavailable", http.StatusServiceUnavailable)
		return
	}
	s.wireguardConfigMu.Lock()
	defer s.wireguardConfigMu.Unlock()
	if _, err := os.Lstat(s.wireguardClientConfig); err == nil {
		http.Error(w, "Download the current Windows configuration before regenerating the peer", http.StatusConflict)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		s.logger.Error("check pending Windows WireGuard configuration before rotation", "error", err)
		http.Error(w, "WireGuard peer rotation is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	status, err := s.wireguardControl.Status(ctx)
	if err != nil {
		s.logger.Error("read active WireGuard peer status", "error", err)
		http.Error(w, "WireGuard peer rotation is unavailable", http.StatusServiceUnavailable)
		return
	}
	clientData, _, err := wireguard.ClientConfiguration(s.wireguardEndpoint, status, s.wireguardKeepalive)
	if err != nil {
		s.logger.Error("generate replacement Windows WireGuard configuration", "error", err)
		http.Error(w, "WireGuard peer rotation failed", http.StatusInternalServerError)
		return
	}
	defer clear(clientData)
	if err := s.wireguardControl.Rotate(ctx, clientData); err != nil {
		s.logger.Error("rotate Windows WireGuard peer", "error", err)
		http.Error(w, "WireGuard peer rotation failed. The previous peer remains active.", http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
}
func (s *Server) addWhitelistEntry(w http.ResponseWriter, r *http.Request) {
	s.changeWhitelist(w, r, "add")
}
func (s *Server) nameWhitelistEntry(w http.ResponseWriter, r *http.Request) {
	s.changeWhitelist(w, r, "name")
}
func (s *Server) removeWhitelistEntry(w http.ResponseWriter, r *http.Request) {
	s.changeWhitelist(w, r, "remove")
}

func (s *Server) changeWhitelist(w http.ResponseWriter, r *http.Request, action string) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	id, authenticated := s.session(r)
	if !authenticated {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.sessions.CheckCSRF(id, r.FormValue("csrf")) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if s.whitelist == nil {
		http.Error(w, "Whitelist management is unavailable", http.StatusServiceUnavailable)
		return
	}
	var err error
	switch action {
	case "add":
		err = s.whitelist.Add(r.FormValue("entry"), r.FormValue("name"))
	case "name":
		err = s.whitelist.SetName(r.FormValue("entry"), r.FormValue("name"))
	default:
		err = s.whitelist.Remove(r.FormValue("entry"))
	}
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, whitelist.ErrInvalidEntry), errors.Is(err, whitelist.ErrInvalidEntryName):
			status = http.StatusBadRequest
		case errors.Is(err, ErrDuplicateWhitelistEntry), errors.Is(err, ErrWhitelistEntryNotFound):
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.invalidateComponentHealth()
	http.Redirect(w, r, "/access-control", http.StatusSeeOther)
}

func (s *Server) session(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return "", false
	}
	_, authenticated, ok := s.sessions.State(cookie.Value)
	return cookie.Value, ok && authenticated
}

func (s *Server) enrollmentOnlySession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return "", false
	}
	return cookie.Value, s.sessions.EnrollmentOnly(cookie.Value)
}

func (s *Server) setCookie(w http.ResponseWriter, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: id, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	s.renderStatus(w, http.StatusOK, name, data)
}

func (s *Server) renderStatus(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Error("render admin page", "error", err)
	}
}
