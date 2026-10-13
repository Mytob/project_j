package admin

import (
	"embed"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/whitelist"
	"github.com/Mytob/project_j/internal/wireguard"
	"github.com/skip2/go-qrcode"
)

//go:embed templates/*.html
var templateFiles embed.FS

type Server struct {
	credential            *auth.Credential
	sessions              *auth.Sessions
	totpStore             *auth.TOTPStore
	limiter               *auth.LoginLimiter
	whitelist             *WhitelistManager
	wireguardClientConfig string
	templates             *template.Template
	logger                *slog.Logger
	now                   func() time.Time
	authTransitionMu      sync.Mutex
}

const totpReauthenticationLifetime = 5 * time.Minute

func New(credential *auth.Credential, logger *slog.Logger, whitelistManager ...*WhitelistManager) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	server := &Server{credential: credential, sessions: auth.NewSessions(auth.DefaultSessionLifetime), limiter: auth.NewLoginLimiter(0, 0), templates: template.Must(template.ParseFS(templateFiles, "templates/*.html")), logger: logger, now: time.Now}
	if len(whitelistManager) > 0 {
		server.whitelist = whitelistManager[0]
	}
	return server
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("POST /totp/enroll/start", s.startTOTPEnrollment)
	mux.HandleFunc("POST /totp/enroll/confirm", s.confirmTOTPEnrollmentHandler)
	mux.HandleFunc("POST /totp/enroll/cancel", s.cancelTOTPEnrollment)
	mux.HandleFunc("GET /dashboard", s.dashboard)
	mux.HandleFunc("POST /whitelist/add", s.addWhitelistEntry)
	mux.HandleFunc("POST /whitelist/remove", s.removeWhitelistEntry)
	mux.HandleFunc("GET /wireguard/config", s.downloadWireGuardConfig)
	return s.securityHeaders(mux)
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
	if _, err := wireguard.LoadRetainedClientConfig(path); err != nil {
		return err
	}
	s.wireguardClientConfig = path
	return nil
}

// ConfigureTOTPStore connects validated persistent TOTP state to the admin
// authentication boundary. The web configuration routes are added in the
// following implementation stage.
func (s *Server) ConfigureTOTPStore(store *auth.TOTPStore) error {
	if store == nil {
		return errors.New("TOTP state store is unavailable")
	}
	s.totpStore = store
	return nil
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
	data := map[string]any{"CSRF": csrf}
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

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	id, authenticated := s.session(r)
	if !authenticated {
		if enrollmentID, ok := s.enrollmentOnlySession(r); ok {
			s.recoveryEnrollmentPage(w, enrollmentID)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
	}
	data := map[string]any{"CSRF": csrf, "Entries": entries, "WhitelistEnabled": s.whitelist != nil, "WireGuardEnabled": s.wireguardClientConfig != ""}
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
	s.render(w, "dashboard.html", data)
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
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
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
		s.logger.Error("load retained Windows WireGuard configuration", "error", err)
		http.Error(w, "Windows WireGuard configuration is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="jellyfin-proxy.conf"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
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
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
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
