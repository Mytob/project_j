package admin

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/totp"
	"github.com/Mytob/project_j/internal/wireguard"
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

func TestHealthEndpoint(t *testing.T) {
	response := request(newTestServer(t), http.MethodGet, "/healthz", nil, nil)
	if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("health endpoint: status=%d body=%q", response.Code, response.Body.String())
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

func TestConfirmTOTPEnrollmentRevokesAllSessionsAfterPersistence(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "admin.json")
	if err := auth.SaveCredential(credentialPath, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	store, err := auth.InitializeTOTPStore(filepath.Join(root, "totp-state.json"), key)
	if err != nil {
		t.Fatal(err)
	}
	server := New(credential, nil)
	if err := server.ConfigureTOTPStore(store); err != nil {
		t.Fatal(err)
	}
	secret, err := store.BeginEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0)
	validCode, err := totp.Code(secret, now)
	clear(secret)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.confirmTOTPEnrollment("000000", now); err == nil {
		t.Fatal("incorrect enrollment code activated TOTP")
	}
	if _, authenticated, ok := server.sessions.State(first); !ok || !authenticated {
		t.Fatal("failed activation revoked an existing session")
	}
	if err := server.confirmTOTPEnrollment(validCode, now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first, second} {
		if _, _, ok := server.sessions.State(id); ok {
			t.Fatal("successful activation did not revoke every existing session")
		}
	}
}

func TestWireGuardDownloadRequiresAuthenticationAndIsNonCacheable(t *testing.T) {
	root := t.TempDir()
	paths, err := wireguard.EnsureProvisioned(filepath.Join(root, "wireguard"), wireguard.ProvisionOptions{
		Endpoint: "vpn.example.test:51820", ListenPort: 51820,
		ServerAddress: netip.MustParsePrefix("10.66.66.1/24"),
		ClientAddress: netip.MustParsePrefix("10.66.66.2/32"), Keepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(paths.ClientPath)
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(root, "admin.json")
	if err := auth.SaveCredential(credentialPath, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	server := New(credential, nil)
	if err := server.ConfigureWireGuardConfig(paths.ClientPath); err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	unauthorized := request(handler, "GET", "/wireguard/config", nil, nil)
	if unauthorized.Code != http.StatusSeeOther || unauthorized.Header().Get("Location") != "/" {
		t.Fatalf("anonymous config download status/location = %d %q", unauthorized.Code, unauthorized.Header().Get("Location"))
	}

	id, _, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "admin_session", Value: id}
	dashboard := request(handler, "GET", "/dashboard", nil, cookie)
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "/wireguard/config") {
		t.Fatalf("dashboard did not expose config download: %d %s", dashboard.Code, dashboard.Body.String())
	}
	for attempt := 0; attempt < 2; attempt++ {
		response := request(handler, "GET", "/wireguard/config", nil, cookie)
		if response.Code != http.StatusOK {
			t.Fatalf("download status %d: %s", response.Code, response.Body.String())
		}
		if response.Body.String() != string(expected) {
			t.Fatal("download did not return the retained Windows config")
		}
		if response.Header().Get("Cache-Control") == "" || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("WireGuard download is cacheable")
		}
		if response.Header().Get("Content-Type") != "application/octet-stream" || response.Header().Get("Content-Disposition") != `attachment; filename="jellyfin-proxy.conf"` {
			t.Fatalf("unexpected download headers: %#v", response.Header())
		}
	}
}

func TestWireGuardDownloadFailsClosedWhenRetainedFilePermissionsChange(t *testing.T) {
	root := t.TempDir()
	paths, err := wireguard.EnsureProvisioned(filepath.Join(root, "wireguard"), wireguard.ProvisionOptions{
		Endpoint: "vpn.example.test:51820", ListenPort: 51820,
		ServerAddress: netip.MustParsePrefix("10.66.66.1/24"),
		ClientAddress: netip.MustParsePrefix("10.66.66.2/32"), Keepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(root, "admin.json")
	if err := auth.SaveCredential(credentialPath, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	server := New(credential, nil)
	if err := server.ConfigureWireGuardConfig(paths.ClientPath); err != nil {
		t.Fatal(err)
	}
	id, _, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.ClientPath, 0o644); err != nil {
		t.Fatal(err)
	}
	response := request(server.Handler(), "GET", "/wireguard/config", nil, &http.Cookie{Name: "admin_session", Value: id})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("download with broad file permissions returned %d", response.Code)
	}
}

func TestWhitelistChangesRequireAuthenticatedSessionAndCSRF(t *testing.T) {
	path := t.TempDir() + "/admin.json"
	if err := auth.SaveCredential(path, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryWhitelistStore{}
	applier := &recordingPolicy{}
	manager := newManager(store, applier)
	server := New(credential, nil, manager)
	handler := server.Handler()
	anonymous := request(handler, "POST", "/whitelist/add", url.Values{"csrf": {"wrong"}, "entry": {"192.0.2.1"}}, nil)
	if anonymous.Code != http.StatusSeeOther {
		t.Fatalf("anonymous whitelist change status %d", anonymous.Code)
	}

	id, csrf, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "admin_session", Value: id}
	badCSRF := request(handler, "POST", "/whitelist/add", url.Values{"csrf": {"wrong"}, "entry": {"192.0.2.1"}}, cookie)
	if badCSRF.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF status %d", badCSRF.Code)
	}
	if len(store.entries) != 0 || len(applier.applied) != 1 {
		t.Fatal("invalid CSRF request changed the whitelist or Caddy")
	}
	valid := request(handler, "POST", "/whitelist/add", url.Values{"csrf": {csrf}, "entry": {"192.0.2.1"}}, cookie)
	if valid.Code != http.StatusSeeOther {
		t.Fatalf("valid change status %d, body %s", valid.Code, valid.Body.String())
	}
}
