package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Mytob/project_j/internal/auth"
)

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	path := t.TempDir() + "/admin.json"
	if err := auth.SaveCredential(path, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	return New(credential, nil).Handler()
}

func request(handler http.Handler, method, target string, body url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body.Encode()))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestAuthenticationSessionCSRFAndLogout(t *testing.T) {
	handler := newTestServer(t)
	unauthorized := request(handler, "GET", "/dashboard", nil, nil)
	if unauthorized.Code != http.StatusSeeOther || unauthorized.Header().Get("Location") != "/" {
		t.Fatalf("unauthorized dashboard: %d %q", unauthorized.Code, unauthorized.Header().Get("Location"))
	}

	page := request(handler, "GET", "/", nil, nil)
	if page.Code != http.StatusOK {
		t.Fatalf("login page status %d", page.Code)
	}
	match := csrfPattern.FindStringSubmatch(page.Body.String())
	if len(match) != 2 {
		t.Fatal("login page did not include CSRF token")
	}
	var anonymous *http.Cookie
	for _, c := range page.Result().Cookies() {
		if c.Name == "admin_session" {
			anonymous = c
		}
	}
	if anonymous == nil || !anonymous.HttpOnly || !anonymous.Secure || anonymous.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie lacks security flags: %#v", anonymous)
	}
	if page.Header().Get("Cache-Control") == "" {
		t.Fatal("login page is cacheable")
	}

	badCSRF := request(handler, "POST", "/login", url.Values{"csrf": {"wrong"}, "password": {"correct test administrator password"}}, anonymous)
	if badCSRF.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF status %d", badCSRF.Code)
	}

	login := request(handler, "POST", "/login", url.Values{"csrf": {match[1]}, "password": {"correct test administrator password"}}, anonymous)
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != "/dashboard" {
		t.Fatalf("login status/redirect: %d %q body=%s", login.Code, login.Header().Get("Location"), login.Body.String())
	}
	var authenticated *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == "admin_session" {
			authenticated = c
		}
	}
	if authenticated == nil || authenticated.Value == anonymous.Value {
		t.Fatal("login did not rotate the session ID")
	}

	dashboard := request(handler, "GET", "/dashboard", nil, authenticated)
	if dashboard.Code != http.StatusOK {
		t.Fatalf("dashboard status %d", dashboard.Code)
	}
	logoutCSRF := csrfPattern.FindStringSubmatch(dashboard.Body.String())
	if len(logoutCSRF) != 2 {
		t.Fatal("dashboard did not include logout CSRF token")
	}
	logout := request(handler, "POST", "/logout", url.Values{"csrf": {logoutCSRF[1]}}, authenticated)
	if logout.Code != http.StatusSeeOther || logout.Header().Get("Location") != "/" {
		t.Fatalf("logout status/redirect: %d %q", logout.Code, logout.Header().Get("Location"))
	}
	if c := logout.Result().Cookies()[0]; c.MaxAge >= 0 {
		t.Fatalf("logout cookie not expired: %#v", c)
	}
	if after := request(handler, "GET", "/dashboard", nil, authenticated); after.Code != http.StatusSeeOther {
		t.Fatalf("revoked session still accesses dashboard: %d", after.Code)
	}
}

func TestWrongPasswordAndLogoutCSRF(t *testing.T) {
	handler := newTestServer(t)
	page := request(handler, "GET", "/", nil, nil)
	token := csrfPattern.FindStringSubmatch(page.Body.String())[1]
	cookie := page.Result().Cookies()[0]
	bad := request(handler, "POST", "/login", url.Values{"csrf": {token}, "password": {"wrong password value"}}, cookie)
	if bad.Code != http.StatusUnauthorized || !strings.Contains(bad.Body.String(), "password was not accepted") {
		t.Fatalf("wrong password response: %d %s", bad.Code, bad.Body.String())
	}
	if badLogout := request(handler, "POST", "/logout", url.Values{"csrf": {"wrong"}}, cookie); badLogout.Code != http.StatusForbidden {
		t.Fatalf("bad logout CSRF status %d", badLogout.Code)
	}
}
