package admin

import (
	"bufio"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/security"
	"github.com/Mytob/project_j/internal/totp"
	"github.com/Mytob/project_j/internal/wireguard"
)

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
var totpSecretPattern = regexp.MustCompile(`Manual setup secret: <code>([A-Z2-7]+)</code>`)

func initialState(t *testing.T, handler http.Handler, cookie *http.Cookie) map[string]any {
	t.Helper()
	response := request(handler, http.MethodGet, "/api/initial", nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("admin bootstrap status = %d: %s", response.Code, response.Body.String())
	}
	var state map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode admin bootstrap: %v", err)
	}
	return state
}

func newTOTPTestServer(t *testing.T) (*Server, http.Handler, *auth.TOTPStore, string) {
	t.Helper()
	root := t.TempDir()
	credentialPath := filepath.Join(root, "admin.json")
	if err := auth.SaveCredential(credentialPath, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
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
	return server, server.Handler(), store, filepath.Join(root, "totp-state.json")
}

func activateTestTOTP(t *testing.T, store *auth.TOTPStore, at time.Time) []byte {
	t.Helper()
	secret, err := store.BeginEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.Code(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmEnrollment(code, at); err != nil {
		t.Fatal(err)
	}
	return secret
}

func newAnonymousLogin(t *testing.T, handler http.Handler) (*http.Cookie, string) {
	t.Helper()
	page := request(handler, http.MethodGet, "/", nil, nil)
	csrf := csrfPattern.FindStringSubmatch(page.Body.String())
	if page.Code != http.StatusOK || len(csrf) != 2 {
		t.Fatalf("login page status/CSRF: %d %s", page.Code, page.Body.String())
	}
	for _, cookie := range page.Result().Cookies() {
		if cookie.Name == "admin_session" {
			return cookie, csrf[1]
		}
	}
	t.Fatal("login page did not set a session")
	return nil, ""
}

func codeOutsideWindow(secret []byte, at time.Time) string {
	current := at.Unix() / int64(totp.Period/time.Second)
	accepted := map[string]bool{}
	for step := current - 1; step <= current+1; step++ {
		if step >= 0 {
			value, _ := totp.Code(secret, time.Unix(step*int64(totp.Period/time.Second), 0))
			accepted[value] = true
		}
	}
	for candidate := 0; candidate < 1_000_000; candidate++ {
		value := fmt.Sprintf("%06d", candidate)
		if !accepted[value] {
			return value
		}
	}
	panic("no invalid TOTP code available")
}

func expiredCodeOutsideWindow(secret []byte, at time.Time) string {
	current := at.Unix() / int64(totp.Period/time.Second)
	accepted := map[string]bool{}
	for step := current - 1; step <= current+1; step++ {
		if step >= 0 {
			value, _ := totp.Code(secret, time.Unix(step*int64(totp.Period/time.Second), 0))
			accepted[value] = true
		}
	}
	for step := current - 2; step >= 0; step-- {
		candidate, _ := totp.Code(secret, time.Unix(step*int64(totp.Period/time.Second), 0))
		if !accepted[candidate] {
			return candidate
		}
	}
	panic("no expired TOTP code available")
}

func loginTestAdmin(t *testing.T, server *Server) *http.Cookie {
	t.Helper()
	handler := server.Handler()
	page := request(handler, http.MethodGet, "/", nil, nil)
	csrf := csrfPattern.FindStringSubmatch(page.Body.String())
	if len(csrf) != 2 {
		t.Fatal("login form is missing CSRF")
	}
	var anonymous *http.Cookie
	for _, cookie := range page.Result().Cookies() {
		if cookie.Name == "admin_session" {
			anonymous = cookie
		}
	}
	if anonymous == nil {
		t.Fatal("login page did not set a session")
	}
	login := request(handler, http.MethodPost, "/login", url.Values{"csrf": {csrf[1]}, "password": {"correct test administrator password"}}, anonymous)
	if login.Code != http.StatusSeeOther {
		t.Fatalf("valid password login status = %d", login.Code)
	}
	for _, cookie := range login.Result().Cookies() {
		if cookie.Name == "admin_session" {
			return cookie
		}
	}
	t.Fatal("login did not set authenticated session")
	return nil
}

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

func TestAdminBootstrapRequiresAuthenticationAndReturnsNoSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	if err := auth.SaveCredential(path, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	server := New(credential, nil)
	handler := server.Handler()
	if response := request(handler, http.MethodGet, "/api/initial", nil, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous bootstrap status = %d", response.Code)
	}
	cookie := loginTestAdmin(t, server)
	response := request(handler, http.MethodGet, "/api/initial", nil, cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("authenticated bootstrap status/content type = %d %q", response.Code, response.Header().Get("Content-Type"))
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["csrf"] == "" || payload["version"] == "" || payload["totp_secret"] != nil {
		t.Fatalf("bootstrap has missing public state or exposed secret: %#v", payload)
	}
	if response.Header().Get("Cache-Control") == "" || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("bootstrap cache policy = %q", response.Header().Get("Cache-Control"))
	}
}

func TestAdminBootstrapReturnsEmptyWhitelistAsArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	if err := auth.SaveCredential(path, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := newManager(&memoryWhitelistStore{}, &recordingPolicy{})
	server := New(credential, nil, manager)
	cookie := loginTestAdmin(t, server)
	response := request(server.Handler(), http.MethodGet, "/api/initial", nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d", response.Code)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	var entries []string
	if err := json.Unmarshal(payload["whitelist"], &entries); err != nil {
		t.Fatalf("empty whitelist is not an array: %s (%v)", payload["whitelist"], err)
	}
	if entries == nil || len(entries) != 0 {
		t.Fatalf("empty whitelist = %#v, want empty array", entries)
	}
	var namedEntries []map[string]any
	if err := json.Unmarshal(payload["whitelist_entries"], &namedEntries); err != nil || namedEntries == nil || len(namedEntries) != 0 {
		t.Fatalf("empty named whitelist is not an array: %s (%v)", payload["whitelist_entries"], err)
	}
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

func TestClientIPTrustsOnlyExplicitPrivateProxyNetwork(t *testing.T) {
	server := New(nil, nil)
	if err := server.ConfigureSecurityEventWriter(t.TempDir(), []byte("01234567890123456789012345678901"), []string{"172.30.253.0/24"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.8:443"
	request.Header.Set(clientIPHeader, "198.51.100.10")
	if got, err := server.clientIP(request); err != nil || got != "203.0.113.8" {
		t.Fatalf("untrusted peer forwarded header = %q, %v", got, err)
	}
	request.RemoteAddr = "172.30.253.11:8080"
	if got, err := server.clientIP(request); err != nil || got != "198.51.100.10" {
		t.Fatalf("trusted proxy source = %q, %v", got, err)
	}
	request.Header.Set(clientIPHeader, "198.51.100.10, 203.0.113.8")
	if _, err := server.clientIP(request); err == nil {
		t.Fatal("accepted an ambiguous forwarded address list")
	}
	request.RemoteAddr = "172.30.254.11:8080"
	request.Header.Set(clientIPHeader, "198.51.100.10")
	if got, err := server.clientIP(request); err != nil || got != "172.30.254.11" {
		t.Fatalf("peer outside trusted network used forwarded address: %q, %v", got, err)
	}
}

func TestAdminLoginWritesSignedFailureAndSuccessEvents(t *testing.T) {
	server, handler, _, _ := newTOTPTestServer(t)
	eventDir := filepath.Join(t.TempDir(), "events")
	key := []byte("01234567890123456789012345678901")
	if err := server.ConfigureSecurityEventWriter(eventDir, key, []string{"172.30.253.0/24"}); err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.Date(2026, 10, 17, 15, 0, 0, 0, time.UTC) }
	cookie, csrf := newAnonymousLogin(t, handler)
	login := func(password string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"csrf": {csrf}, "password": {password}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.RemoteAddr = "172.30.253.11:8080"
		request.Header.Set(clientIPHeader, "198.51.100.88")
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := login("incorrect password"); response.Code != http.StatusUnauthorized {
		t.Fatalf("failed login status = %d", response.Code)
	}
	if response := login("correct test administrator password"); response.Code != http.StatusSeeOther {
		t.Fatalf("successful login status = %d", response.Code)
	}
	items, rejected, err := security.ReadSpool(eventDir, key)
	if err != nil || len(rejected) != 0 || len(items) != 2 {
		t.Fatalf("auth spool has %d valid and %d rejected events: %v", len(items), len(rejected), err)
	}
	kinds := map[security.EventKind]bool{}
	for _, item := range items {
		kinds[item.Event.Kind] = true
		if item.Event.Service != security.Admin || item.Event.IP != "198.51.100.88" {
			t.Fatalf("wrong service or client identity in event: %+v", item.Event)
		}
	}
	if !kinds[security.LoginFailure] || !kinds[security.LoginSuccess] {
		t.Fatalf("missing failed or successful login events: %+v", items)
	}
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

	if dashboard := request(handler, "GET", "/dashboard", nil, authenticated); dashboard.Code != http.StatusOK {
		t.Fatalf("dashboard status %d", dashboard.Code)
	}
	logoutCSRF, ok := initialState(t, handler, authenticated)["csrf"].(string)
	if !ok || logoutCSRF == "" {
		t.Fatal("admin bootstrap did not include logout CSRF token")
	}
	logout := request(handler, "POST", "/logout", url.Values{"csrf": {logoutCSRF}}, authenticated)
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

func TestPasswordChangeVerifiesCSRFCurrentPasswordAndRevokesSessions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "data", "admin-credential.json")
	if err := auth.SaveCredential(path, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	server := New(credential, nil)
	if err := server.ConfigureCredentialPath(path); err != nil {
		t.Fatal(err)
	}
	firstID, csrf, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	secondID, _, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	firstCookie := &http.Cookie{Name: "admin_session", Value: firstID}
	handler := server.Handler()
	if badCSRF := request(handler, http.MethodPost, "/password/change", url.Values{"current_password": {"correct test administrator password"}}, firstCookie); badCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", badCSRF.Code)
	}
	badCurrent := request(handler, http.MethodPost, "/password/change", url.Values{"csrf": {csrf}, "current_password": {"wrong current password"}, "new_password": {"new secure administrator password"}, "confirm_password": {"new secure administrator password"}}, firstCookie)
	if badCurrent.Code != http.StatusUnauthorized {
		t.Fatalf("incorrect current password status = %d", badCurrent.Code)
	}
	short := request(handler, http.MethodPost, "/password/change", url.Values{"csrf": {csrf}, "current_password": {"correct test administrator password"}, "new_password": {"too short"}, "confirm_password": {"too short"}}, firstCookie)
	if short.Code != http.StatusBadRequest {
		t.Fatalf("short replacement status = %d", short.Code)
	}
	changed := request(handler, http.MethodPost, "/password/change", url.Values{"csrf": {csrf}, "current_password": {"correct test administrator password"}, "new_password": {"new secure administrator password"}, "confirm_password": {"new secure administrator password"}}, firstCookie)
	if changed.Code != http.StatusSeeOther || changed.Header().Get("Location") != "/?password=changed" {
		t.Fatalf("password change status/location = %d %q", changed.Code, changed.Header().Get("Location"))
	}
	if _, _, ok := server.sessions.State(firstID); ok {
		t.Fatal("current session remained active")
	}
	if _, _, ok := server.sessions.State(secondID); ok {
		t.Fatal("other administrator session remained active")
	}
	if !credential.Verify("new secure administrator password") || credential.Verify("correct test administrator password") {
		t.Fatal("active credential did not change")
	}
	restarted, err := auth.LoadCredential(path)
	if err != nil || !restarted.Verify("new secure administrator password") {
		t.Fatalf("replacement was not available after restart: %v", err)
	}
}

func TestPasswordChangeRequiresFreshTOTPWhenEnabled(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	credentialPath := filepath.Join(t.TempDir(), "admin-credential.json")
	if err := auth.SaveCredential(credentialPath, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigureCredentialPath(credentialPath); err != nil {
		t.Fatal(err)
	}
	cookie := loginTestAdmin(t, server)
	enrolledAt := time.Unix(1_700_000_010, 0)
	secret := activateTestTOTP(t, store, enrolledAt)
	defer clear(secret)
	changeAt := enrolledAt.Add(time.Minute)
	server.now = func() time.Time { return changeAt }
	csrf := initialState(t, handler, cookie)["csrf"].(string)
	form := url.Values{
		"csrf":             {csrf},
		"current_password": {"correct test administrator password"},
		"new_password":     {"new secure administrator password"},
		"confirm_password": {"new secure administrator password"},
	}
	missingCode := request(handler, http.MethodPost, "/password/change", form, cookie)
	if missingCode.Code != http.StatusUnauthorized || !strings.Contains(missingCode.Body.String(), "authenticator code") {
		t.Fatalf("missing authenticator code response = %d %q", missingCode.Code, missingCode.Body.String())
	}
	form.Set("code", codeOutsideWindow(secret, changeAt))
	wrongCode := request(handler, http.MethodPost, "/password/change", form, cookie)
	if wrongCode.Code != http.StatusUnauthorized || !server.credential.Verify("correct test administrator password") {
		t.Fatalf("incorrect authenticator code changed password: status=%d", wrongCode.Code)
	}
	validCode, err := totp.Code(secret, changeAt)
	if err != nil {
		t.Fatal(err)
	}
	form.Set("code", validCode)
	changed := request(handler, http.MethodPost, "/password/change", form, cookie)
	if changed.Code != http.StatusSeeOther || changed.Header().Get("Location") != "/?password=changed" {
		t.Fatalf("valid authenticator code did not change password: status=%d location=%q body=%s", changed.Code, changed.Header().Get("Location"), changed.Body.String())
	}
	if !server.credential.Verify("new secure administrator password") || server.credential.Verify("correct test administrator password") {
		t.Fatal("password was not replaced after successful authenticator verification")
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

func TestTOTPEnrollmentRequiresFreshPasswordAndVerifyCode(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	cookie := loginTestAdmin(t, server)
	state := initialState(t, handler, cookie)
	if state["totp_status"] != string(auth.TOTPUnconfigured) {
		t.Fatalf("unconfigured bootstrap status = %v", state["totp_status"])
	}
	csrf := state["csrf"].(string)
	wrongPassword := request(handler, http.MethodPost, "/totp/enroll/start", url.Values{"csrf": {csrf}, "password": {"wrong password"}}, cookie)
	if wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("wrong reauthentication response: %d %s", wrongPassword.Code, wrongPassword.Body.String())
	}
	start := request(handler, http.MethodPost, "/totp/enroll/start", url.Values{"csrf": {csrf}, "password": {"correct test administrator password"}}, cookie)
	if start.Code != http.StatusSeeOther || start.Header().Get("Location") != "/security" {
		t.Fatalf("valid reauthentication did not return to dashboard: %d %q", start.Code, start.Header().Get("Location"))
	}
	state = initialState(t, handler, cookie)
	secretText, secretOK := state["totp_secret"].(string)
	qrText, qrOK := state["totp_qr_code"].(string)
	if state["totp_status"] != string(auth.TOTPPending) || state["totp_setup_visible"] != true || !secretOK || secretText == "" || !qrOK || !strings.HasPrefix(qrText, "data:image/png;base64,") {
		t.Fatalf("reauthenticated bootstrap did not expose pending authenticator setup: %#v", state)
	}
	png, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(qrText, "data:image/png;base64,"))
	if err != nil || len(png) < 8 || string(png[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatal("setup QR image is not a valid local PNG")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretText)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	if !strings.Contains(totpProvisioningURI(secret), "issuer=Jellyfin+Proxy") {
		t.Fatal("provisioning URI has incorrect issuer metadata")
	}
	csrf = state["csrf"].(string)
	badCode := request(handler, http.MethodPost, "/totp/enroll/confirm", url.Values{"csrf": {csrf}, "code": {"invalid"}}, cookie)
	if badCode.Code != http.StatusBadRequest || store.Status() != auth.TOTPPending {
		t.Fatalf("incorrect initial code changed enrollment: status=%d state=%s", badCode.Code, store.Status())
	}
	validCode, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirmed := request(handler, http.MethodPost, "/totp/enroll/confirm", url.Values{"csrf": {csrf}, "code": {validCode}}, cookie)
	if confirmed.Code != http.StatusSeeOther || store.Status() != auth.TOTPEnabled {
		t.Fatalf("valid confirmation did not activate TOTP: status=%d state=%s body=%s", confirmed.Code, store.Status(), confirmed.Body.String())
	}
	if _, _, ok := server.sessions.State(cookie.Value); ok {
		t.Fatal("activation did not revoke the enrolling session")
	}
}

func TestAdminBootstrapShowsConfiguredBuildInformation(t *testing.T) {
	server, handler, _, _ := newTOTPTestServer(t)
	server.ConfigureBuildInfo("1.1.1", "abc123def456")
	cookie := loginTestAdmin(t, server)
	state := initialState(t, handler, cookie)
	if state["version"] != "1.1.1" || state["build_number"] != "abc123def456" {
		t.Fatalf("admin bootstrap build information = version %v, build %v", state["version"], state["build_number"])
	}
}

func TestDashboardTOTPDisableRequiresPasswordAndFreshCodeThenRevokesSessions(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	cookie := loginTestAdmin(t, server)
	enrolledAt := time.Unix(1_700_000_010, 0)
	secret := activateTestTOTP(t, store, enrolledAt)
	defer clear(secret)
	otherSession, _, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	disableAt := enrolledAt.Add(30 * time.Second)
	server.now = func() time.Time { return disableAt }
	state := initialState(t, handler, cookie)
	if state["totp_status"] != string(auth.TOTPEnabled) {
		t.Fatalf("enabled authenticator missing from bootstrap: %#v", state)
	}
	csrf := state["csrf"].(string)
	if response := request(handler, http.MethodPost, "/totp/disable", url.Values{"password": {"correct test administrator password"}, "code": {"123456"}}, cookie); response.Code != http.StatusForbidden {
		t.Fatalf("disable accepted missing CSRF: %d", response.Code)
	}
	validCode, err := totp.Code(secret, disableAt)
	if err != nil {
		t.Fatal(err)
	}
	wrongPassword := request(handler, http.MethodPost, "/totp/disable", url.Values{"csrf": {csrf}, "password": {"wrong password"}, "code": {validCode}}, cookie)
	if wrongPassword.Code != http.StatusUnauthorized || store.Status() != auth.TOTPEnabled {
		t.Fatalf("disable with a wrong password changed TOTP state: status=%d state=%s", wrongPassword.Code, store.Status())
	}
	wrongCode := codeOutsideWindow(secret, disableAt)
	invalidCode := request(handler, http.MethodPost, "/totp/disable", url.Values{"csrf": {csrf}, "password": {"correct test administrator password"}, "code": {wrongCode}}, cookie)
	if invalidCode.Code != http.StatusUnauthorized || store.Status() != auth.TOTPEnabled {
		t.Fatalf("disable with an invalid code changed TOTP state: status=%d state=%s", invalidCode.Code, store.Status())
	}
	disabled := request(handler, http.MethodPost, "/totp/disable", url.Values{"csrf": {csrf}, "password": {"correct test administrator password"}, "code": {validCode}}, cookie)
	if disabled.Code != http.StatusSeeOther || disabled.Header().Get("Location") != "/?totp=disabled" || store.Status() != auth.TOTPUnconfigured {
		t.Fatalf("valid disable response/state: status=%d location=%q state=%s", disabled.Code, disabled.Header().Get("Location"), store.Status())
	}
	if after := request(handler, http.MethodGet, "/dashboard", nil, cookie); after.Code != http.StatusSeeOther {
		t.Fatalf("disable left the previous session authenticated: %d", after.Code)
	}
	if _, _, ok := server.sessions.State(otherSession); ok {
		t.Fatal("disable did not revoke every administrator session")
	}
	login := request(handler, http.MethodGet, "/?totp=disabled", nil, nil)
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), "Authenticator disabled. Sign in with your administrator password.") || strings.Contains(login.Body.String(), `id="code"`) {
		t.Fatalf("disabled login page did not confirm password-only sign-in: %d %s", login.Code, login.Body.String())
	}
}

func TestTOTPEnrollmentRequiresCSRFAndCancellationIsPersistent(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	cookie := loginTestAdmin(t, server)
	csrf := initialState(t, handler, cookie)["csrf"].(string)
	if response := request(handler, http.MethodPost, "/totp/enroll/start", url.Values{"password": {"correct test administrator password"}}, cookie); response.Code != http.StatusForbidden {
		t.Fatalf("enrollment accepted missing CSRF: %d", response.Code)
	}
	if response := request(handler, http.MethodPost, "/totp/enroll/start", url.Values{"csrf": {csrf}, "password": {"correct test administrator password"}}, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("enrollment start status = %d", response.Code)
	}
	view := initialState(t, handler, cookie)
	secret, ok := view["totp_secret"].(string)
	if !ok || secret == "" || view["totp_setup_visible"] != true {
		t.Fatal("pending setup secret was not visible after fresh password verification")
	}
	csrf = view["csrf"].(string)
	cancel := request(handler, http.MethodPost, "/totp/enroll/cancel", url.Values{"csrf": {csrf}}, cookie)
	if cancel.Code != http.StatusSeeOther || store.Status() != auth.TOTPUnconfigured {
		t.Fatalf("cancel did not clear pending setup: status=%d state=%s", cancel.Code, store.Status())
	}
	if _, _, ok := server.sessions.State(cookie.Value); ok {
		t.Fatal("cancellation did not revoke the session that viewed the pending secret")
	}
}

func TestTOTPProvisioningURIHasExpectedAuthenticatorParameters(t *testing.T) {
	secret := []byte("01234567890123456789")
	uri := totpProvisioningURI(secret)
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		t.Fatalf("invalid provisioning URI: %q err=%v", uri, err)
	}
	query := parsed.Query()
	if query.Get("secret") != base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret) || query.Get("issuer") != "Jellyfin Proxy" || query.Get("algorithm") != "SHA1" || query.Get("digits") != "6" || query.Get("period") != "30" {
		t.Fatalf("unexpected provisioning parameters: %v", query)
	}
}

func TestTOTPLoginRequiresPasswordAndFreshUnusedCode(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	enrolledAt := time.Unix(1_700_000_010, 0)
	secret := activateTestTOTP(t, store, enrolledAt)
	defer clear(secret)
	loginAt := enrolledAt.Add(totp.Period)
	server.now = func() time.Time { return loginAt }
	loginForm := request(handler, http.MethodGet, "/", nil, nil)
	csrfMatch := csrfPattern.FindStringSubmatch(loginForm.Body.String())
	if len(csrfMatch) != 2 || !strings.Contains(loginForm.Body.String(), `id="code" name="code"`) {
		t.Fatal("enabled TOTP did not render the required code control")
	}
	var browserSession *http.Cookie
	for _, cookie := range loginForm.Result().Cookies() {
		if cookie.Name == "admin_session" {
			browserSession = cookie
		}
	}
	if browserSession == nil {
		t.Fatal("TOTP login page did not set a session")
	}
	csrf := csrfMatch[1]
	post := func(code string) *httptest.ResponseRecorder {
		values := url.Values{"csrf": {csrf}, "password": {"correct test administrator password"}}
		if code != "" {
			values.Set("code", code)
		}
		return request(handler, http.MethodPost, "/login", values, browserSession)
	}
	for name, code := range map[string]string{
		"missing":   "",
		"incorrect": codeOutsideWindow(secret, loginAt),
		"expired":   expiredCodeOutsideWindow(secret, loginAt),
	} {
		response := post(code)
		if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "password or authenticator code was not accepted") {
			t.Errorf("%s TOTP login status/body = %d %s", name, response.Code, response.Body.String())
		}
		if _, authenticated, ok := server.sessions.State(browserSession.Value); ok && authenticated {
			t.Errorf("%s TOTP attempt created an authenticated session", name)
		}
	}
	validCode, err := totp.Code(secret, loginAt)
	if err != nil {
		t.Fatal(err)
	}
	valid := post(validCode)
	if valid.Code != http.StatusSeeOther || valid.Header().Get("Location") != "/dashboard" {
		t.Fatalf("password-plus-TOTP login status/redirect: %d %q body=%s", valid.Code, valid.Header().Get("Location"), valid.Body.String())
	}
	var authenticated *http.Cookie
	for _, cookie := range valid.Result().Cookies() {
		if cookie.Name == "admin_session" {
			authenticated = cookie
		}
	}
	if authenticated == nil || authenticated.Value == browserSession.Value {
		t.Fatal("successful TOTP login did not rotate the session")
	}
	if response := request(handler, http.MethodGet, "/dashboard", nil, authenticated); response.Code != http.StatusOK {
		t.Errorf("fully authenticated session cannot access dashboard: %d", response.Code)
	}
	sessionCSRF, _, _ := server.sessions.State(authenticated.Value)
	if response := request(handler, http.MethodPost, "/wireguard/config", url.Values{"csrf": {sessionCSRF}}, authenticated); response.Code != http.StatusServiceUnavailable {
		t.Errorf("authenticated session did not pass auth boundary for unconfigured WireGuard fixture: %d", response.Code)
	}
	replayCookie, replayCSRF := newAnonymousLogin(t, handler)
	replay := request(handler, http.MethodPost, "/login", url.Values{"csrf": {replayCSRF}, "password": {"correct test administrator password"}, "code": {validCode}}, replayCookie)
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("reused login code returned %d", replay.Code)
	}
}

func TestRecoveryLoginIsRestrictedUntilFreshAuthenticatorActivation(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	enrolledAt := time.Unix(1_700_000_010, 0)
	activateTestTOTP(t, store, enrolledAt)
	if err := store.RequireFreshEnrollment(); err != nil {
		t.Fatal(err)
	}
	now := enrolledAt.Add(2 * totp.Period)
	server.now = func() time.Time { return now }
	cookie, csrf := newAnonymousLogin(t, handler)
	if response := request(handler, http.MethodPost, "/login", url.Values{"csrf": {csrf}, "password": {"correct test administrator password"}}, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("recovery password login returned %d: %s", response.Code, response.Body.String())
	} else {
		for _, issued := range response.Result().Cookies() {
			if issued.Name == "admin_session" {
				cookie = issued
			}
		}
	}
	page := request(handler, http.MethodGet, "/dashboard", nil, cookie)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Authenticator recovery") || strings.Contains(page.Body.String(), "Whitelist") || strings.Contains(page.Body.String(), "WireGuard") {
		t.Fatalf("recovery session did not render a restricted setup page: %d %s", page.Code, page.Body.String())
	}
	csrfMatch := csrfPattern.FindStringSubmatch(page.Body.String())
	if len(csrfMatch) != 2 {
		t.Fatal("recovery page did not render CSRF token")
	}
	if response := request(handler, http.MethodPost, "/whitelist/add", url.Values{"csrf": {csrfMatch[1]}, "entry": {"192.0.2.1"}}, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("recovery session reached whitelist mutation: %d", response.Code)
	}
	if response := request(handler, http.MethodPost, "/wireguard/config", url.Values{"csrf": {csrfMatch[1]}}, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("recovery session reached protected download: %d", response.Code)
	}
	if response := request(handler, http.MethodPost, "/totp/enroll/start", url.Values{"csrf": {csrfMatch[1]}, "password": {"correct test administrator password"}}, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("recovery enrollment start returned %d: %s", response.Code, response.Body.String())
	}
	page = request(handler, http.MethodGet, "/dashboard", nil, cookie)
	secretMatch := totpSecretPattern.FindStringSubmatch(page.Body.String())
	if page.Code != http.StatusOK || len(secretMatch) != 2 {
		t.Fatalf("recovery enrollment secret was not shown after password check: %d %s", page.Code, page.Body.String())
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretMatch[1])
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	code, err := totp.Code(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	csrfMatch = csrfPattern.FindStringSubmatch(page.Body.String())
	confirmed := request(handler, http.MethodPost, "/totp/enroll/confirm", url.Values{"csrf": {csrfMatch[1]}, "code": {code}}, cookie)
	if confirmed.Code != http.StatusSeeOther || store.Status() != auth.TOTPEnabled || store.RequiresEnrollment() {
		t.Fatalf("fresh recovery enrollment did not activate TOTP: %d status=%s", confirmed.Code, store.Status())
	}
	if response := request(handler, http.MethodGet, "/dashboard", nil, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("enrollment session survived activation: %d", response.Code)
	}
	freshCookie, freshCSRF := newAnonymousLogin(t, handler)
	if response := request(handler, http.MethodPost, "/login", url.Values{"csrf": {freshCSRF}, "password": {"correct test administrator password"}}, freshCookie); response.Code != http.StatusUnauthorized {
		t.Fatalf("password-only login succeeded after re-enrollment: %d", response.Code)
	}
	freshCode, err := totp.Code(secret, now.Add(totp.Period))
	if err != nil {
		t.Fatal(err)
	}
	accepted := request(handler, http.MethodPost, "/login", url.Values{"csrf": {freshCSRF}, "password": {"correct test administrator password"}, "code": {freshCode}}, freshCookie)
	if accepted.Code != http.StatusSeeOther {
		t.Fatalf("password-plus-new-TOTP login failed: %d %s", accepted.Code, accepted.Body.String())
	}
}

func TestConcurrentTOTPLoginsConsumeCodeOnce(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	enrolledAt := time.Unix(1_700_000_010, 0)
	secret := activateTestTOTP(t, store, enrolledAt)
	defer clear(secret)
	loginAt := enrolledAt.Add(totp.Period)
	server.now = func() time.Time { return loginAt }
	code, err := totp.Code(secret, loginAt)
	if err != nil {
		t.Fatal(err)
	}
	cookies := make([]*http.Cookie, 2)
	csrf := make([]string, 2)
	for i := range cookies {
		cookies[i], csrf[i] = newAnonymousLogin(t, handler)
	}
	start := make(chan struct{})
	responses := make([]*httptest.ResponseRecorder, 2)
	var wait sync.WaitGroup
	for i := range responses {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			<-start
			responses[i] = request(handler, http.MethodPost, "/login", url.Values{"csrf": {csrf[i]}, "password": {"correct test administrator password"}, "code": {code}}, cookies[i])
		}(i)
	}
	close(start)
	wait.Wait()
	successes := 0
	for _, response := range responses {
		if response.Code == http.StatusSeeOther {
			successes++
		} else if response.Code != http.StatusUnauthorized {
			t.Errorf("unexpected concurrent login status: %d %s", response.Code, response.Body.String())
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent logins = %d, want exactly one", successes)
	}
}

func TestConcurrentActivationCannotLeavePasswordOnlySession(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	at := time.Unix(1_700_000_010, 0)
	server.now = func() time.Time { return at }
	secret, err := store.BeginEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	activationCode, err := totp.Code(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	activationID, activationCSRF, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	if !server.sessions.GrantRecentPasswordVerification(activationID, time.Minute) {
		t.Fatal("could not grant test enrollment authorization")
	}
	loginCookie, loginCSRF := newAnonymousLogin(t, handler)
	start := make(chan struct{})
	var loginResponse, activationResponse *httptest.ResponseRecorder
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		loginResponse = request(handler, http.MethodPost, "/login", url.Values{"csrf": {loginCSRF}, "password": {"correct test administrator password"}}, loginCookie)
	}()
	go func() {
		defer wait.Done()
		<-start
		activationResponse = request(handler, http.MethodPost, "/totp/enroll/confirm", url.Values{"csrf": {activationCSRF}, "code": {activationCode}}, &http.Cookie{Name: "admin_session", Value: activationID})
	}()
	close(start)
	wait.Wait()
	if activationResponse.Code != http.StatusSeeOther || store.Status() != auth.TOTPEnabled {
		t.Fatalf("activation did not complete: status=%d TOTP=%s body=%s", activationResponse.Code, store.Status(), activationResponse.Body.String())
	}
	if loginResponse.Code != http.StatusUnauthorized && loginResponse.Code != http.StatusSeeOther {
		t.Fatalf("concurrent password-only login status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	if _, _, ok := server.sessions.State(activationID); ok {
		t.Fatal("activation session survived activation")
	}
	for _, cookie := range loginResponse.Result().Cookies() {
		if cookie.Name == "admin_session" && cookie.MaxAge >= 0 {
			if _, authenticated, ok := server.sessions.State(cookie.Value); ok && authenticated {
				t.Fatal("password-only login completed across activation and survived session revocation")
			}
		}
	}
}

func TestTOTPLoginFailsClosedWhenReplayStateCannotBePersisted(t *testing.T) {
	server, handler, store, statePath := newTOTPTestServer(t)
	enrolledAt := time.Unix(1_700_000_010, 0)
	secret := activateTestTOTP(t, store, enrolledAt)
	defer clear(secret)
	loginAt := enrolledAt.Add(totp.Period)
	server.now = func() time.Time { return loginAt }
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := newAnonymousLogin(t, handler)
	code, err := totp.Code(secret, loginAt)
	if err != nil {
		t.Fatal(err)
	}
	response := request(handler, http.MethodPost, "/login", url.Values{"csrf": {csrf}, "password": {"correct test administrator password"}, "code": {code}}, cookie)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("login succeeded when replay state could not be persisted: %d", response.Code)
	}
	if _, authenticated, ok := server.sessions.State(cookie.Value); ok && authenticated {
		t.Fatal("storage failure created an authenticated session")
	}
}

func TestTOTPEnrollmentSecretAndConfirmationRequirePasswordReauthentication(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	cookie := loginTestAdmin(t, server)
	if _, err := store.BeginEnrollment(); err != nil {
		t.Fatal(err)
	}
	state := initialState(t, handler, cookie)
	if _, ok := state["totp_secret"]; ok {
		t.Fatal("pending setup secret was visible without password reauthentication")
	}
	csrf := state["csrf"].(string)
	response := request(handler, http.MethodPost, "/totp/enroll/confirm", url.Values{"csrf": {csrf}, "code": {"123456"}}, cookie)
	if response.Code != http.StatusForbidden {
		t.Fatalf("confirmation without recent password verification returned %d", response.Code)
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
	getDownload := request(handler, http.MethodGet, "/wireguard/config", nil, nil)
	if getDownload.Code == http.StatusOK {
		t.Fatalf("state-changing GET download returned the private config")
	}
	if _, err := os.Stat(paths.ClientPath); err != nil {
		t.Fatalf("rejected GET consumed the config: %v", err)
	}
	unauthorized := request(handler, http.MethodPost, "/wireguard/config", nil, nil)
	if unauthorized.Code != http.StatusSeeOther || unauthorized.Header().Get("Location") != "/" {
		t.Fatalf("anonymous config download status/location = %d %q", unauthorized.Code, unauthorized.Header().Get("Location"))
	}

	id, csrf, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "admin_session", Value: id}
	dashboard := request(handler, "GET", "/wireguard", nil, cookie)
	if dashboard.Code != http.StatusOK || dashboard.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("WireGuard SPA route status/content type = %d %q", dashboard.Code, dashboard.Header().Get("Content-Type"))
	}
	if state := initialState(t, handler, cookie); state["wireguard_config_available"] != true {
		t.Fatalf("WireGuard bootstrap did not expose the retained client config: %#v", state)
	}
	withoutCSRF := request(handler, http.MethodPost, "/wireguard/config", nil, cookie)
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("download without CSRF returned %d, want forbidden", withoutCSRF.Code)
	}
	if _, err := os.Stat(paths.ClientPath); err != nil {
		t.Fatalf("rejected download consumed the config: %v", err)
	}
	response := request(handler, http.MethodPost, "/wireguard/config", url.Values{"csrf": {csrf}}, cookie)
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
	if _, err := os.Stat(paths.ClientPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful download did not delete its server copy: %v", err)
	}
	second := request(handler, http.MethodPost, "/wireguard/config", url.Values{"csrf": {csrf}}, cookie)
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second download returned %d, want one-time download rejection", second.Code)
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
	id, csrf, err := server.sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.ClientPath, 0o644); err != nil {
		t.Fatal(err)
	}
	response := request(server.Handler(), http.MethodPost, "/wireguard/config", url.Values{"csrf": {csrf}}, &http.Cookie{Name: "admin_session", Value: id})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("download with broad file permissions returned %d", response.Code)
	}
}

func TestWireGuardRotationWaitsForOneTimeDownload(t *testing.T) {
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
	if err := server.ConfigureWireGuardControl(filepath.Join(root, "unused.sock"), "vpn.example.test:51820", 25); err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	cookie := loginTestAdmin(t, server)
	csrf, _, ok := server.sessions.State(cookie.Value)
	if !ok {
		t.Fatal("authenticated session is missing")
	}
	rotate := func() *httptest.ResponseRecorder {
		t.Helper()
		return request(handler, http.MethodPost, "/wireguard/rotate", url.Values{"csrf": {csrf}}, cookie)
	}

	blocked := rotate()
	if blocked.Code != http.StatusConflict || !strings.Contains(blocked.Body.String(), "Download the current Windows configuration") {
		t.Fatalf("rotation with an unconsumed config returned %d: %s", blocked.Code, blocked.Body.String())
	}
	if _, err := os.Stat(paths.ClientPath); err != nil {
		t.Fatalf("blocked rotation changed the current downloadable config: %v", err)
	}

	download := request(handler, http.MethodPost, "/wireguard/config", url.Values{"csrf": {csrf}}, cookie)
	if download.Code != http.StatusOK {
		t.Fatalf("one-time download returned %d: %s", download.Code, download.Body.String())
	}
	if _, err := os.Stat(paths.ClientPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful download did not consume the config: %v", err)
	}
	if next := rotate(); next.Code != http.StatusServiceUnavailable {
		t.Fatalf("rotation after consuming the config returned %d, want control-service failure after passing the download gate", next.Code)
	}
	if _, err := os.Stat(paths.ClientPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed rotation restored an unavailable config: %v", err)
	}
	if response := request(handler, http.MethodPost, "/wireguard/config/delete", url.Values{"csrf": {csrf}}, cookie); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("manual config deletion endpoint returned %d, want method not allowed", response.Code)
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
	valid := request(handler, "POST", "/whitelist/add", url.Values{"csrf": {csrf}, "entry": {"192.0.2.1"}, "name": {"Home phone"}}, cookie)
	if valid.Code != http.StatusSeeOther {
		t.Fatalf("valid change status %d, body %s", valid.Code, valid.Body.String())
	}
	entries, err := manager.ListEntries()
	if err != nil || len(entries) != 1 || entries[0].Address != "192.0.2.1/32" || entries[0].Name != "Home phone" {
		t.Fatalf("added named entry = %#v, %v", entries, err)
	}
	nameResponse := request(handler, "POST", "/whitelist/name", url.Values{"csrf": {csrf}, "entry": {"192.0.2.1"}, "name": {"Living room TV"}}, cookie)
	if nameResponse.Code != http.StatusSeeOther {
		t.Fatalf("friendly-name update status %d, body %s", nameResponse.Code, nameResponse.Body.String())
	}
	state := initialState(t, handler, cookie)
	encodedEntries, err := json.Marshal(state["whitelist_entries"])
	if err != nil {
		t.Fatal(err)
	}
	var responseEntries []map[string]string
	if err := json.Unmarshal(encodedEntries, &responseEntries); err != nil || len(responseEntries) != 1 || responseEntries[0]["address"] != "192.0.2.1/32" || responseEntries[0]["name"] != "Living room TV" {
		t.Fatalf("bootstrap whitelist entries = %s, %v", encodedEntries, err)
	}
}

func TestStatisticsPageRequiresAdministratorSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	if err := auth.SaveCredential(path, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	server := New(credential, nil)
	handler := server.Handler()
	unauthorized := request(handler, http.MethodGet, "/statistics", nil, nil)
	if unauthorized.Code != http.StatusSeeOther || unauthorized.Header().Get("Location") != "/" {
		t.Fatalf("unauthenticated statistics request = %d, %q", unauthorized.Code, unauthorized.Header().Get("Location"))
	}
	for _, path := range []string{"/statistics/events", "/statistics/history?range=24h"} {
		response := request(handler, http.MethodGet, path, nil, nil)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated statistics endpoint %s returned %d", path, response.Code)
		}
	}
	for _, path := range []string{"/dashboard", "/access-control", "/security", "/wireguard"} {
		response := request(handler, http.MethodGet, path, nil, nil)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
			t.Fatalf("unauthenticated admin page %s = %d, %q", path, response.Code, response.Header().Get("Location"))
		}
	}
	adminCookie := loginTestAdmin(t, server)
	page := request(handler, http.MethodGet, "/statistics", nil, adminCookie)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="root"`) {
		t.Fatalf("authenticated statistics SPA route = %d %s", page.Code, page.Body.String())
	}
	policy := page.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "style-src 'self'") || strings.Contains(policy, "unsafe-inline") {
		t.Fatalf("statistics route has an unexpected style policy: %q", policy)
	}
	fallback, err := templateFiles.ReadFile("templates/statistics.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := templateFiles.ReadFile("templates/statistics.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fallback), `<progress class="disk-bar" id="disk-used-bar"`) || strings.Contains(string(fallback), "style=") || strings.Contains(string(script), ".style.") || !strings.Contains(string(script), "diskUsedBar.value") {
		t.Fatal("server-rendered statistics fallback requires inline styles")
	}
}

type fixedCaddyHealth struct{ err error }

func (check fixedCaddyHealth) CheckHealth() error { return check.err }

type countingCaddyHealth struct{ calls atomic.Int32 }

func (check *countingCaddyHealth) CheckHealth() error {
	check.calls.Add(1)
	return nil
}

func TestComponentHealthSharesChecksForFifteenSeconds(t *testing.T) {
	server, _, _, _ := newTOTPTestServer(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	check := &countingCaddyHealth{}
	server.ConfigureComponentHealth(check, "")
	server.componentHealth(nil)
	server.componentHealth(nil)
	if got := check.calls.Load(); got != 1 {
		t.Fatalf("Caddy checks within one cache interval = %d, want 1", got)
	}
	now = now.Add(15 * time.Second)
	server.componentHealth(nil)
	if got := check.calls.Load(); got != 2 {
		t.Fatalf("Caddy checks after cache expiry = %d, want 2", got)
	}
}

func TestCPUHealthUsesHysteresis(t *testing.T) {
	var pressure cpuPressureState
	for _, sample := range []struct {
		value    float64
		degraded bool
		phase    string
	}{
		{97, false, "confirming"},
		{98, true, "degraded"},
		{90, true, "degraded"},
		{85, true, "recovering"},
		{84, false, "recovered"},
		{99, false, "confirming"},
		{60, false, "healthy"},
		{99, false, "confirming"},
	} {
		degraded, phase := pressure.Observe(sample.value)
		if degraded != sample.degraded || phase != sample.phase {
			t.Fatalf("Observe(%.1f) = %t, %q; want %t, %q", sample.value, degraded, phase, sample.degraded, sample.phase)
		}
	}
}

func TestUnchangedHealthObservationDoesNotRewriteDurableState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "health-state.json")
	server := New(nil, nil)
	if err := server.ConfigureHealthState(path); err != nil {
		t.Fatal(err)
	}
	checked := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	server.recordHealth([]componentStatus{{Name: "Caddy / proxy", State: "Healthy", Detail: "private health check succeeded"}}, checked)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	items := server.recordHealth([]componentStatus{{Name: "Caddy / proxy", State: "Healthy", Detail: "private health check succeeded"}}, checked.Add(time.Minute))
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("unchanged health state was persisted again: before %s after %s", before, after)
	}
	if len(items) != 1 || !items[0].CheckedAt.Equal(checked.Add(time.Minute)) {
		t.Fatalf("in-memory health freshness was not updated: %#v", items)
	}
}

func TestAdminNavigationUsesSeparatePagesAndOverviewReportsHealth(t *testing.T) {
	server, handler, _, _ := newTOTPTestServer(t)
	server.whitelist = newManager(&memoryWhitelistStore{entries: []string{"192.0.2.1"}}, &recordingPolicy{})
	server.wireguardClientConfig = "configured"
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	heartbeat := filepath.Join(t.TempDir(), "wireguard-health")
	if err := os.WriteFile(heartbeat, []byte(strconv.FormatInt(now.Add(-5*time.Second).Unix(), 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	server.ConfigureComponentHealth(fixedCaddyHealth{}, heartbeat)
	cookie := loginTestAdmin(t, server)

	for _, route := range []string{"/dashboard", "/health", "/access-control", "/security", "/wireguard", "/statistics", "/settings", "/about"} {
		response := request(handler, http.MethodGet, route, nil, cookie)
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(response.Body.String(), `id="root"`) {
			t.Errorf("admin route %s did not serve the SPA shell: status=%d content-type=%q", route, response.Code, response.Header().Get("Content-Type"))
		}
	}
	state := initialState(t, handler, cookie)
	components, ok := state["components"].([]any)
	if !ok {
		t.Fatalf("bootstrap components have unexpected type: %T", state["components"])
	}
	observed := map[string]map[string]any{}
	for _, raw := range components {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("bootstrap component has unexpected type %T", raw)
		}
		observed[item["name"].(string)] = item
	}
	for _, name := range []string{"Admin backend", "Access control", "Caddy / proxy", "WireGuard interface", "Windows peer", "Jellyfin endpoint", "Host metrics", "Proxy metrics", "Admin container", "Host metrics container", "Caddy container", "WireGuard container"} {
		if observed[name] == nil {
			t.Errorf("bootstrap health is missing component %q", name)
		}
	}
	if observed["Caddy / proxy"]["detail"] != "Caddy responded through its private admin socket." || observed["WireGuard interface"]["detail"] != "A recent heartbeat confirms that the interface is up. This does not prove peer reachability." || observed["Windows peer"]["detail"] != "The private WireGuard status socket is not configured." || observed["Host metrics"]["state"] != "Unknown" || observed["Proxy metrics"]["state"] != "Unknown" || observed["Admin container"]["state"] != "Unknown" {
		t.Fatalf("bootstrap health did not reflect observed evidence: %#v", observed)
	}
}

func TestAboutAPIRequiresAdminAndCombinesInstalledAndRunningVersions(t *testing.T) {
	server, _, _, _ := newTOTPTestServer(t)
	metadataPath := filepath.Join(t.TempDir(), "install-info.json")
	if err := os.WriteFile(metadataPath, []byte(`{"version":1,"installed_at":"2026-10-20T11:12:13Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigureInstallMetadata(metadataPath); err != nil {
		t.Fatal(err)
	}
	server.ConfigureBuildInfo("1.6.0-dev", "abc1234")
	observer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/inventory" {
			t.Fatalf("unexpected about inventory request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ubuntu_version":"Ubuntu 26.04.1 LTS","proxyctl_version":"1.6.0-dev","docker_engine_version":"29.1.3","compose_version":"2.40.3","services":[{"service":"caddy","image":"jellyfin-proxy/caddy:1.6.0-dev","component_version":"2.11.7"}]}`)
	}))
	defer observer.Close()
	server.ConfigureContainerHealth(observer.URL)
	handler := server.Handler()
	if response := request(handler, http.MethodGet, "/api/about", nil, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated about status = %d", response.Code)
	}
	cookie := loginTestAdmin(t, server)
	response := request(handler, http.MethodGet, "/api/about", nil, cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("authenticated about response = %d %q", response.Code, response.Header().Get("Cache-Control"))
	}
	var value aboutResponse
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value.Version != "1.6.0-dev" || value.BuildID != "abc1234" || value.GoVersion == "" || value.InstalledAt != "2026-10-20T11:12:13Z" || !value.InventoryAvailable || value.UbuntuVersion != "Ubuntu 26.04.1 LTS" || value.ProxyctlVersion != "1.6.0-dev" || value.DockerEngineVersion != "29.1.3" || value.ComposeVersion != "2.40.3" || len(value.Services) != 1 || value.Services[0].ComponentVersion != "2.11.7" {
		t.Fatalf("about response did not distinguish build and running versions: %+v", value)
	}
}

func TestContainerHealthUsesPrivateObserverSnapshot(t *testing.T) {
	observer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/containers" {
			t.Fatalf("unexpected observer request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"service":"admin","state":"running","health":"healthy","restart_count":2,"checked_at":"2026-10-16T12:00:00Z"},{"service":"hostmetrics","state":"running","health":"healthy","restart_count":0,"checked_at":"2026-10-16T12:00:00Z"},{"service":"caddy","state":"running","health":"unhealthy","restart_count":1,"checked_at":"2026-10-16T12:00:00Z"},{"service":"wireguard","state":"exited","health":"none","restart_count":4,"checked_at":"2026-10-16T12:00:00Z"}]`)
	}))
	defer observer.Close()
	server, _, _, _ := newTOTPTestServer(t)
	server.ConfigureContainerHealth(observer.URL)
	components := server.componentHealth(nil)
	states := make(map[string]componentStatus, len(components))
	for _, component := range components {
		states[component.Name] = component
	}
	if states["Admin container"].State != "Healthy" || states["Host metrics container"].State != "Healthy" || states["Caddy container"].State != "Down" || states["WireGuard container"].State != "Down" {
		t.Fatalf("container states did not reflect Docker observer evidence: %#v", states)
	}
	if !strings.Contains(states["Admin container"].Detail, "2 restarts") || !strings.Contains(states["WireGuard container"].Detail, "4 restarts") {
		t.Fatalf("container restart counts were omitted: %#v", states)
	}
}

func TestHealthStatePersistsLastSuccessAndFailureAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "health-state.json")
	server := New(nil, nil)
	if err := server.ConfigureHealthState(path); err != nil {
		t.Fatal(err)
	}
	checked := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	server.recordHealth([]componentStatus{{Name: "Caddy / proxy", State: "Healthy", Detail: "private health check succeeded"}}, checked)
	failed := checked.Add(time.Minute)
	server.recordHealth([]componentStatus{{Name: "Caddy / proxy", State: "Down", Detail: "private health check failed"}}, failed)

	restarted := New(nil, nil)
	if err := restarted.ConfigureHealthState(path); err != nil {
		t.Fatal(err)
	}
	items := restarted.recordHealth([]componentStatus{{Name: "Caddy / proxy", State: "Unknown", Detail: "private health check unavailable"}}, failed.Add(time.Minute))
	if len(items) != 1 || items[0].LastSuccessAt == nil || !items[0].LastSuccessAt.Equal(checked) || items[0].LastFailureAt == nil || !items[0].LastFailureAt.Equal(failed) {
		t.Fatalf("health observation timestamps were not retained: %#v", items)
	}
	events := restarted.recentHealthEvents()
	if len(events) != 2 || events[0].From != "Healthy" || events[0].To != "Down" || events[1].From != "Down" || events[1].To != "Unknown" || events[0].Name != "Caddy / proxy" {
		t.Fatalf("health transition history = %#v", events)
	}
}

func TestWireGuardHealthHeartbeatMustBeRecent(t *testing.T) {
	server, _, _, _ := newTOTPTestServer(t)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "wireguard-health")
	server.wireguardHealthPath = path
	for _, testCase := range []struct {
		name string
		age  time.Duration
		want bool
	}{
		{name: "recent", age: 10 * time.Second, want: true},
		{name: "stale", age: 16 * time.Second},
		{name: "future", age: -6 * time.Second},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			data := strconv.FormatInt(now.Add(-testCase.age).Unix(), 10)
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := server.wireguardHeartbeatHealthy(); got != testCase.want {
				t.Fatalf("heartbeat health = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestHealthDoesNotInferWindowsOrJellyfinFromTunnelHeartbeat(t *testing.T) {
	server, _, _, _ := newTOTPTestServer(t)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	heartbeat := filepath.Join(t.TempDir(), "wireguard-health")
	if err := os.WriteFile(heartbeat, []byte(strconv.FormatInt(now.Unix(), 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	server.ConfigureComponentHealth(fixedCaddyHealth{}, heartbeat)
	items := server.componentHealth(nil)
	states := make(map[string]string, len(items))
	for _, item := range items {
		states[item.Name] = item.State
	}
	if states["Caddy / proxy"] != "Healthy" || states["WireGuard interface"] != "Healthy" {
		t.Fatalf("observed private checks were not healthy: %#v", states)
	}
	for _, name := range []string{"Windows peer", "Jellyfin endpoint", "Host metrics", "Proxy metrics", "Admin container", "Host metrics container", "Caddy container", "WireGuard container"} {
		if states[name] != "Unknown" {
			t.Errorf("unobserved component %q was reported as %q", name, states[name])
		}
	}
	server.ConfigureComponentHealth(fixedCaddyHealth{err: fmt.Errorf("private probe failed")}, heartbeat)
	for _, item := range server.componentHealth(nil) {
		if item.Name == "Caddy / proxy" && item.State != "Down" {
			t.Fatalf("failed private Caddy probe state = %q", item.State)
		}
	}
}

func TestStatisticsSSEEndsWhenAdministratorSessionIsRevoked(t *testing.T) {
	root := t.TempDir()
	credentialPath := filepath.Join(root, "admin.json")
	if err := auth.SaveCredential(credentialPath, "correct test administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	memoryTotal := uint64(10)
	var hostTimestamp atomic.Int64
	hostTimestamp.Store(now.UnixNano())
	hostServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		captured := time.Unix(0, hostTimestamp.Load()).UTC()
		_ = json.NewEncoder(w).Encode(monitoring.HostMetrics{CapturedAt: captured, MemoryTotalBytes: &memoryTotal})
	}))
	defer hostServer.Close()
	proxyPath := filepath.Join(root, "proxy.json")
	proxyData, err := json.Marshal(monitoring.ProxyMetrics{CapturedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxyPath, proxyData, 0o600); err != nil {
		t.Fatal(err)
	}
	history, err := monitoring.OpenHistory(filepath.Join(root, "history"))
	if err != nil {
		t.Fatal(err)
	}
	feed, err := monitoring.NewFeed(hostServer.URL, proxyPath, history, nil)
	if err != nil {
		t.Fatal(err)
	}
	streamContext, stopFeed := context.WithCancel(t.Context())
	defer stopFeed()
	go feed.Start(streamContext)
	server := New(credential, nil)
	if err := server.ConfigureStatistics(feed); err != nil {
		t.Fatal(err)
	}
	cookie := loginTestAdmin(t, server)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	request, err := http.NewRequest(http.MethodGet, httpServer.URL+"/statistics/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(cookie)
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream; charset=utf-8" {
		t.Fatalf("SSE response = %d %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil || line != "retry: 2000\n" {
		t.Fatalf("SSE did not begin with reconnect interval: %q, %v", line, err)
	}
	if line, err = reader.ReadString('\n'); err != nil || line != "\n" {
		t.Fatalf("SSE reconnect interval was not terminated: %q, %v", line, err)
	}
	var initial strings.Builder
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("SSE did not send initial metrics: %v", err)
		}
		initial.WriteString(line)
		if line == "\n" {
			break
		}
	}
	if !strings.Contains(initial.String(), "event: metrics") {
		t.Fatalf("initial SSE event = %q", initial.String())
	}
	var health strings.Builder
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("SSE did not send initial health status: %v", err)
		}
		health.WriteString(line)
		if line == "\n" {
			break
		}
	}
	if !strings.Contains(health.String(), "event: health") || !strings.Contains(health.String(), "Windows peer") {
		t.Fatalf("SSE did not publish authenticated health status: %q", health.String())
	}
	server.sessions.RevokeAll()
	hostTimestamp.Store(time.Now().UTC().UnixNano())
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(remaining), "event: auth-required") {
		t.Fatalf("revoked session stream did not terminate with auth-required: %q", remaining)
	}
}

func TestAdminStylesheetIsServedAsCSS(t *testing.T) {
	response := request(newTestServer(t), http.MethodGet, "/assets/admin.css", nil, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "text/css") || !strings.Contains(response.Body.String(), "prefers-reduced-motion") {
		t.Fatalf("admin stylesheet response = %d %q %s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
}
