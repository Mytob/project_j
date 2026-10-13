package admin

import (
	"embed"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/whitelist"
	"github.com/Mytob/project_j/internal/wireguard"
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
}

func New(credential *auth.Credential, logger *slog.Logger, whitelistManager ...*WhitelistManager) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	server := &Server{credential: credential, sessions: auth.NewSessions(auth.DefaultSessionLifetime), limiter: auth.NewLoginLimiter(0, 0), templates: template.Must(template.ParseFS(templateFiles, "templates/*.html")), logger: logger}
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
	id, csrf, err := s.sessions.Create(false)
	if err != nil {
		http.Error(w, "Unable to start a session", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, id, int(auth.DefaultSessionLifetime.Seconds()))
	s.render(w, "login.html", map[string]any{"CSRF": csrf})
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
	if !s.credential.Verify(r.FormValue("password")) {
		s.limiter.Failed()
		csrf, _, _ := s.sessions.State(oldID)
		s.renderStatus(w, http.StatusUnauthorized, "login.html", map[string]any{"CSRF": csrf, "Error": "The password was not accepted."})
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
	s.render(w, "dashboard.html", map[string]any{"CSRF": csrf, "Entries": entries, "WhitelistEnabled": s.whitelist != nil, "WireGuardEnabled": s.wireguardClientConfig != ""})
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
