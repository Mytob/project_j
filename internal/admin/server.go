package admin

import (
	"embed"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Mytob/project_j/internal/auth"
)

//go:embed templates/*.html
var templateFiles embed.FS

type Server struct {
	credential *auth.Credential
	sessions   *auth.Sessions
	limiter    *auth.LoginLimiter
	templates  *template.Template
	logger     *slog.Logger
}

func New(credential *auth.Credential, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{credential: credential, sessions: auth.NewSessions(auth.DefaultSessionLifetime), limiter: auth.NewLoginLimiter(0, 0), templates: template.Must(template.ParseFS(templateFiles, "templates/*.html")), logger: logger}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /dashboard", s.dashboard)
	return s.securityHeaders(mux)
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
	s.render(w, "dashboard.html", map[string]any{"CSRF": csrf})
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
