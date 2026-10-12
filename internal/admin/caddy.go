package admin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/whitelist"
)

const whitelistImport = "import /etc/caddy/whitelist.caddy"

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// CaddyAPI replaces the single allowlist import in a read-only Caddyfile
// template and submits the complete candidate config through Caddy's private
// admin API. Caddy's /load endpoint keeps the prior config if activation fails.
type CaddyAPI struct {
	client       httpDoer
	templatePath string
	endpoint     string
}

func NewCaddyAPI(socketPath, templatePath string) *CaddyAPI {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
	}}
	return &CaddyAPI{client: &http.Client{Transport: transport, Timeout: 20 * time.Second}, templatePath: templatePath, endpoint: "http://caddy/load"}
}

func (c *CaddyAPI) Apply(entries []string) error {
	data, err := os.ReadFile(c.templatePath)
	if err != nil {
		return fmt.Errorf("read Caddyfile template: %w", err)
	}
	base := string(data)
	if strings.Count(base, whitelistImport) != 1 {
		return fmt.Errorf("Caddyfile template must contain exactly one %q", whitelistImport)
	}
	parsed, err := whitelist.Validate(entries)
	if err != nil {
		return fmt.Errorf("validate whitelist for Caddy: %w", err)
	}
	policy := whitelist.RenderCaddyPolicy(parsed)
	config := strings.Replace(base, whitelistImport, strings.TrimSpace(policy), 1)
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewReader([]byte(config)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/caddyfile")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("request Caddy config load: %w", err)
	}
	defer resp.Body.Close()
	message, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("read Caddy response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Caddy rejected whitelist config (%s): %s", resp.Status, strings.TrimSpace(string(message)))
	}
	return nil
}
