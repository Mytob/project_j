package admin

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestCaddyAPIReplacesOnlyWhitelistImport(t *testing.T) {
	template := "{\n\tadmin unix//run/admin.sock\n}\n\naccess.test {\n\ttls internal\n\timport /etc/caddy/whitelist.caddy\n}\n"
	path := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(path, []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.Method != http.MethodPost || req.URL.Path != "/load" {
			t.Errorf("request = %s %s", req.Method, req.URL.Path)
		}
		if got := req.Header.Get("Content-Type"); got != "text/caddyfile" {
			t.Errorf("content type = %q", got)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "@whitelisted remote_ip 192.0.2.0/24") || strings.Contains(string(body), whitelistImport) {
			t.Errorf("unexpected loaded config: %s", body)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	applier := &CaddyAPI{client: client, templatePath: path, endpoint: "http://caddy/load"}
	if err := applier.Apply([]string{"192.0.2.3/24"}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Caddy API was not called")
	}
}

func TestCaddyAPIRejectsInvalidTemplateAndCaddyErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(path, []byte("no import here"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	applier := &CaddyAPI{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, nil })}, templatePath: path}
	if err := applier.Apply(nil); err == nil {
		t.Fatal("missing whitelist import was accepted")
	}
	if called {
		t.Fatal("Caddy API was called with an invalid template")
	}

	if err := os.WriteFile(path, []byte("access.test { import /etc/caddy/whitelist.caddy }"), 0o600); err != nil {
		t.Fatal(err)
	}
	applier.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Status: "400 Bad Request", Body: io.NopCloser(strings.NewReader("invalid config")), Header: make(http.Header)}, nil
	})}
	if err := applier.Apply([]string{"192.0.2.1"}); err == nil || !strings.Contains(err.Error(), "invalid config") {
		t.Fatalf("Caddy error = %v", err)
	}
}
