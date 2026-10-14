package admin

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/totp"
	"github.com/Mytob/project_j/internal/wireguard"
)

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
var totpSecretPattern = regexp.MustCompile(`Manual setup secret: <code>([A-Z2-7]+)</code>`)

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

func TestTOTPEnrollmentRenderedControlsRequireFreshPasswordAndVerifyCode(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	cookie := loginTestAdmin(t, server)
	dashboard := request(handler, http.MethodGet, "/dashboard", nil, cookie)
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), `action="/totp/enroll/start"`) {
		t.Fatalf("unconfigured dashboard did not render enrollment controls: %d %s", dashboard.Code, dashboard.Body.String())
	}
	csrf := csrfPattern.FindStringSubmatch(dashboard.Body.String())[1]
	wrongPassword := request(handler, http.MethodPost, "/totp/enroll/start", url.Values{"csrf": {csrf}, "password": {"wrong password"}}, cookie)
	if wrongPassword.Code != http.StatusUnauthorized || strings.Contains(wrongPassword.Body.String(), "data:image/png") {
		t.Fatalf("wrong reauthentication response: %d %s", wrongPassword.Code, wrongPassword.Body.String())
	}
	start := request(handler, http.MethodPost, "/totp/enroll/start", url.Values{"csrf": {csrf}, "password": {"correct test administrator password"}}, cookie)
	if start.Code != http.StatusSeeOther || start.Header().Get("Location") != "/dashboard" {
		t.Fatalf("valid reauthentication did not return to dashboard: %d %q", start.Code, start.Header().Get("Location"))
	}
	dashboard = request(handler, http.MethodGet, "/dashboard", nil, cookie)
	body := dashboard.Body.String()
	secretMatch := totpSecretPattern.FindStringSubmatch(body)
	if dashboard.Code != http.StatusOK || len(secretMatch) != 2 || !strings.Contains(body, `alt="Authenticator setup QR code"`) || !strings.Contains(body, `action="/totp/enroll/confirm"`) {
		t.Fatalf("reauthenticated dashboard did not render setup QR and confirmation form: %d %s", dashboard.Code, body)
	}
	qr := regexp.MustCompile(`src="(data:image/png;base64,[A-Za-z0-9+/=]+)"`).FindStringSubmatch(html.UnescapeString(body))
	if len(qr) != 2 {
		t.Fatalf("QR code was not embedded as a locally generated image: %s", body)
	}
	png, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(qr[1], "data:image/png;base64,"))
	if err != nil || len(png) < 8 || string(png[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatal("setup QR image is not a valid local PNG")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretMatch[1])
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	if !strings.Contains(totpProvisioningURI(secret), "issuer=Jellyfin+Proxy") {
		t.Fatal("provisioning URI has incorrect issuer metadata")
	}
	csrf = csrfPattern.FindStringSubmatch(body)[1]
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

func TestDashboardShowsConfiguredBuildInformation(t *testing.T) {
	server, handler, _, _ := newTOTPTestServer(t)
	server.ConfigureBuildInfo("1.1.1", "abc123def456")
	cookie := loginTestAdmin(t, server)
	dashboard := request(handler, http.MethodGet, "/dashboard", nil, cookie)
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "Version: <code>1.1.1</code>") || !strings.Contains(dashboard.Body.String(), "Build number: <code>abc123def456</code>") {
		t.Fatalf("dashboard did not show build information: %d %s", dashboard.Code, dashboard.Body.String())
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
	dashboard := request(handler, http.MethodGet, "/dashboard", nil, cookie)
	body := dashboard.Body.String()
	if dashboard.Code != http.StatusOK || !strings.Contains(body, `action="/totp/disable"`) || !strings.Contains(body, `id="totp-disable-password"`) || !strings.Contains(body, `id="totp-disable-code"`) {
		t.Fatalf("enabled dashboard is missing disable controls: %d %s", dashboard.Code, body)
	}
	csrf := csrfPattern.FindStringSubmatch(body)[1]
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
	dashboard := request(handler, http.MethodGet, "/dashboard", nil, cookie)
	csrf := csrfPattern.FindStringSubmatch(dashboard.Body.String())[1]
	if response := request(handler, http.MethodPost, "/totp/enroll/start", url.Values{"password": {"correct test administrator password"}}, cookie); response.Code != http.StatusForbidden {
		t.Fatalf("enrollment accepted missing CSRF: %d", response.Code)
	}
	if response := request(handler, http.MethodPost, "/totp/enroll/start", url.Values{"csrf": {csrf}, "password": {"correct test administrator password"}}, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("enrollment start status = %d", response.Code)
	}
	view := request(handler, http.MethodGet, "/dashboard", nil, cookie)
	secret := totpSecretPattern.FindStringSubmatch(view.Body.String())
	if len(secret) != 2 {
		t.Fatal("pending setup secret was not visible after fresh password verification")
	}
	csrf = csrfPattern.FindStringSubmatch(view.Body.String())[1]
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
	if response := request(handler, http.MethodGet, "/wireguard/config", nil, authenticated); response.Code != http.StatusServiceUnavailable {
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
	if response := request(handler, http.MethodGet, "/wireguard/config", nil, cookie); response.Code != http.StatusSeeOther {
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

func mustCode(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()
	code, err := totp.Code(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestTOTPEnrollmentSecretAndConfirmationRequirePasswordReauthentication(t *testing.T) {
	server, handler, store, _ := newTOTPTestServer(t)
	cookie := loginTestAdmin(t, server)
	if _, err := store.BeginEnrollment(); err != nil {
		t.Fatal(err)
	}
	dashboard := request(handler, http.MethodGet, "/dashboard", nil, cookie)
	if strings.Contains(dashboard.Body.String(), "Manual setup secret") {
		t.Fatal("pending setup secret was visible without password reauthentication")
	}
	csrf := csrfPattern.FindStringSubmatch(dashboard.Body.String())[1]
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
