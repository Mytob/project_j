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
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/containerhealth"
	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/whitelist"
	"github.com/Mytob/project_j/internal/wireguard"
	"github.com/skip2/go-qrcode"
)

//go:embed templates/* frontend/dist
var templateFiles embed.FS

type Server struct {
	credential            *auth.Credential
	sessions              *auth.Sessions
	totpStore             *auth.TOTPStore
	limiter               *auth.LoginLimiter
	passwordLimiter       *auth.LoginLimiter
	credentialPath        string
	healthStatePath       string
	healthMu              sync.Mutex
	healthRecords         map[string]healthRecord
	healthEvents          []healthEvent
	whitelist             *WhitelistManager
	wireguardClientConfig string
	wireguardControl      wireguard.ControlClient
	wireguardEndpoint     string
	wireguardKeepalive    uint16
	templates             *template.Template
	logger                *slog.Logger
	now                   func() time.Time
	authTransitionMu      sync.Mutex
	version               string
	buildNumber           string
	statistics            *monitoring.Feed
	caddyHealth           interface{ CheckHealth() error }
	containerHealth       *containerhealth.Client
	wireguardHealthPath   string
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
	mux.HandleFunc("GET /", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("POST /totp/enroll/start", s.startTOTPEnrollment)
	mux.HandleFunc("POST /totp/enroll/confirm", s.confirmTOTPEnrollmentHandler)
	mux.HandleFunc("POST /totp/enroll/cancel", s.cancelTOTPEnrollment)
	mux.HandleFunc("POST /totp/disable", s.disableTOTP)
	mux.HandleFunc("POST /password/change", s.changePassword)
	mux.HandleFunc("GET /dashboard", s.dashboard)
	mux.HandleFunc("GET /health", s.healthPage)
	mux.HandleFunc("GET /access-control", s.accessControlPage)
	mux.HandleFunc("GET /security", s.securityPage)
	mux.HandleFunc("GET /wireguard", s.wireGuardPage)
	mux.HandleFunc("GET /statistics", s.statisticsPage)
	mux.HandleFunc("GET /statistics/events", s.statisticsEvents)
	mux.HandleFunc("GET /statistics/history", s.statisticsHistory)
	mux.HandleFunc("POST /whitelist/add", s.addWhitelistEntry)
	mux.HandleFunc("POST /whitelist/remove", s.removeWhitelistEntry)
	mux.HandleFunc("GET /wireguard/config", s.downloadWireGuardConfig)
	mux.HandleFunc("POST /wireguard/config/delete", s.deleteWireGuardConfig)
	mux.HandleFunc("POST /wireguard/rotate", s.rotateWireGuardConfig)
	return s.securityHeaders(mux)
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
	return nil
}

// ConfigureComponentHealth connects private service checks to the Overview.
// The WireGuard heartbeat is written by its existing container entrypoint and
// mounted read-only into admin; no Docker socket or public health endpoint is used.
func (s *Server) ConfigureComponentHealth(caddy interface{ CheckHealth() error }, wireguardHeartbeatPath string) {
	s.caddyHealth = caddy
	s.wireguardHealthPath = wireguardHeartbeatPath
}

// ConfigureContainerHealth connects the private, read-only Docker observer.
func (s *Server) ConfigureContainerHealth(origin string) {
	s.containerHealth = containerhealth.NewClient(origin)
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
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
			csrf, _, _ := s.sessions.State(oldID)
			s.renderStatus(w, http.StatusUnauthorized, "login.html", map[string]any{"CSRF": csrf, "Error": "The password or authenticator code was not accepted.", "TOTPRequired": true})
			return
		}
	}
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
	if s.whitelist != nil {
		var err error
		entries, err = s.whitelist.List()
		if err != nil {
			http.Error(w, "Whitelist is unavailable", http.StatusServiceUnavailable)
			return
		}
		if entries == nil {
			entries = []string{}
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
		"CSRF": csrf, "Entries": entries, "WhitelistEnabled": s.whitelist != nil,
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
	if s.whitelist != nil {
		var err error
		entries, err = s.whitelist.List()
		if err != nil {
			http.Error(w, "Whitelist is unavailable", http.StatusServiceUnavailable)
			return
		}
		if entries == nil {
			entries = []string{}
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
		"whitelist_enabled": s.whitelist != nil, "whitelist": entries,
		"wireguard_enabled": s.wireguardClientConfig != "", "wireguard_config_available": configAvailable, "totp_status": string(status),
		"components": s.componentHealthObserved(entries, wireguardStatus), "health_events": s.recentHealthEvents(),
		"current": monitoring.LiveData{Status: "disconnected"},
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
	var status *wireguard.PeerStatus
	if s.wireguardControl.SocketPath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		observed, err := s.wireguardControl.Status(ctx)
		cancel()
		if err == nil {
			status = &observed
		}
	}
	return s.componentHealthObserved(entries, status)
}

func (s *Server) componentHealthObserved(entries []string, wireguardStatus *wireguard.PeerStatus) []componentStatus {
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
		if current.Host.DiskUsedBytes != nil && current.Host.DiskTotalBytes != nil && *current.Host.DiskTotalBytes > 0 && float64(*current.Host.DiskUsedBytes)/float64(*current.Host.DiskTotalBytes) >= 0.9 {
			state, detail = "Degraded", "Disk usage is at least 90% of measured capacity."
		} else if current.Host.MemoryUsedBytes != nil && current.Host.MemoryTotalBytes != nil && *current.Host.MemoryTotalBytes > 0 && float64(*current.Host.MemoryUsedBytes)/float64(*current.Host.MemoryTotalBytes) >= 0.9 {
			state, detail = "Degraded", "Memory usage is at least 90% of measured capacity."
		} else if current.Host.CPUPercent != nil && *current.Host.CPUPercent >= 95 {
			state, detail = "Degraded", "CPU usage is at least 95% in the latest host sample."
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
		payload, err := json.Marshal(map[string]any{"components": s.componentHealth(entries), "health_events": s.recentHealthEvents()})
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: health\ndata: %s\n\n", payload); err != nil {
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
	_, authenticated := s.session(r)
	if !authenticated {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if s.wireguardClientConfig == "" {
		http.Error(w, "Windows WireGuard configuration is unavailable", http.StatusServiceUnavailable)
		return
	}
	data, err := wireguard.LoadRetainedClientConfig(s.wireguardClientConfig)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Error("load retained Windows WireGuard configuration", "error", err)
		}
		http.Error(w, "Windows WireGuard configuration is unavailable", http.StatusServiceUnavailable)
		return
	}
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
	http.Redirect(w, r, "/wireguard?rotated=1", http.StatusSeeOther)
}

func (s *Server) deleteWireGuardConfig(w http.ResponseWriter, r *http.Request) {
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
	if err := os.Remove(s.wireguardClientConfig); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.logger.Error("delete downloadable Windows WireGuard configuration", "error", err)
		http.Error(w, "Windows WireGuard configuration could not be deleted", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/wireguard?deleted=1", http.StatusSeeOther)
}

func (s *Server) addWhitelistEntry(w http.ResponseWriter, r *http.Request) {
	s.changeWhitelist(w, r, true)
}
func (s *Server) removeWhitelistEntry(w http.ResponseWriter, r *http.Request) {
	s.changeWhitelist(w, r, false)
}

func (s *Server) changeWhitelist(w http.ResponseWriter, r *http.Request, add bool) {
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
	if add {
		err = s.whitelist.Add(r.FormValue("entry"))
	} else {
		err = s.whitelist.Remove(r.FormValue("entry"))
	}
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, whitelist.ErrInvalidEntry):
			status = http.StatusBadRequest
		case errors.Is(err, ErrDuplicateWhitelistEntry), errors.Is(err, ErrWhitelistEntryNotFound):
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
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
