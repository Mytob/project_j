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

func TestCaddyHealthCheckUsesPrivateConfigEndpoint(t *testing.T) {
	called := false
	api := &CaddyAPI{
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			called = true
			if request.Method != http.MethodGet || request.URL.Path != "/config/" {
				t.Errorf("health request = %s %s", request.Method, request.URL.Path)
			}
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
		})},
		healthURL: "http://caddy/config/",
	}
	if err := api.CheckHealth(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Caddy health endpoint was not called")
	}
	api.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	if err := api.CheckHealth(); err == nil {
		t.Fatal("unhealthy Caddy response was accepted")
	}
}

func TestAdminAndAccessHostsAreMarkedNoIndex(t *testing.T) {
	for _, fixture := range []struct {
		filename string
		hosts    []string
	}{
		{"../../deploy/caddy/Caddyfile", []string{"admin.{$BASE_DOMAIN}", "access.{$BASE_DOMAIN}"}},
		{"../../deploy/caddy/Caddyfile.test", []string{"admin.domain.test", "access.domain.test"}},
	} {
		content, err := os.ReadFile(fixture.filename)
		if err != nil {
			t.Fatal(err)
		}
		config := string(content)
		for _, host := range fixture.hosts {
			block := caddySiteBlock(config, host)
			if !strings.Contains(block, `header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet"`) {
				t.Errorf("%s does not mark %s as noindex", fixture.filename, host)
			}
			if !strings.Contains(block, `respond /robots.txt "User-agent: *\nDisallow: /\n" 200`) {
				t.Errorf("%s does not disallow crawlers at %s/robots.txt", fixture.filename, host)
			}
		}
	}
}

func caddySiteBlock(config, host string) string {
	start := strings.Index(config, host+" {")
	if start < 0 {
		return ""
	}
	openingOffset := strings.Index(config[start+len(host):], "{")
	if openingOffset < 0 {
		return ""
	}
	opening := start + len(host) + openingOffset
	depth := 0
	for index := opening; index < len(config); index++ {
		switch config[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return config[start : index+1]
			}
		}
	}
	return config[start:]
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
