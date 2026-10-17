package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type ban struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

func main() {
	socket := flag.String("socket", "/run/caddy-security/control.sock", "private Caddy control socket")
	origin := flag.String("origin", "http://127.0.0.1:8080", "Caddy test origin")
	flag.Parse()
	if err := run(*socket, *origin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(socket, origin string) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	control := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	public := &http.Client{Timeout: 3 * time.Second}
	check := func(path string, status int, body string) error {
		response, err := public.Get(strings.TrimRight(origin, "/") + path)
		if err != nil {
			return fmt.Errorf("GET %s: %w", path, err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil {
			return err
		}
		if response.StatusCode != status || !strings.Contains(string(data), body) {
			return fmt.Errorf("GET %s returned %d %q, expected %d containing %q", path, response.StatusCode, string(data), status, body)
		}
		return nil
	}
	putSnapshot := func(bans []ban) error {
		data, err := json.Marshal(map[string]any{"bans": bans})
		if err != nil {
			return err
		}
		request, err := http.NewRequest(http.MethodPut, "http://caddy/v1/snapshot", bytes.NewReader(data))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := control.Do(request)
		if err != nil {
			return fmt.Errorf("update private Caddy blocklist: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
			return fmt.Errorf("Caddy blocklist update returned %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
		}
		return nil
	}
	if err := check("/admin", http.StatusOK, "admin ok"); err != nil {
		return err
	}
	if err := check("/System/Info/Public", http.StatusOK, "jellyfin ok"); err != nil {
		return err
	}
	if err := putSnapshot([]ban{{IP: "127.0.0.1", ExpiresAt: time.Now().UTC().Add(time.Minute)}}); err != nil {
		return err
	}
	if err := check("/admin", http.StatusForbidden, "Access Denied"); err != nil {
		return err
	}
	if err := check("/System/Info/Public", http.StatusOK, "jellyfin ok"); err != nil {
		return fmt.Errorf("admin ban affected Jellyfin route: %w", err)
	}
	request, err := http.NewRequest(http.MethodGet, "http://caddy/v1/blocked", nil)
	if err != nil {
		return err
	}
	response, err := control.Do(request)
	if err != nil {
		return err
	}
	var blocked map[string]uint64
	err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&blocked)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || blocked["127.0.0.1"] != 1 {
		return fmt.Errorf("Caddy blocked-request aggregation mismatch: status=%d counts=%v err=%v", response.StatusCode, blocked, err)
	}
	if err := putSnapshot(nil); err != nil {
		return err
	}
	if err := check("/admin", http.StatusOK, "admin ok"); err != nil {
		return fmt.Errorf("dynamic unban did not restore admin access: %w", err)
	}
	if err := putSnapshot([]ban{{IP: "127.0.0.1", ExpiresAt: time.Now().UTC().Add(-time.Second)}}); err != nil {
		return err
	}
	if err := check("/admin", http.StatusOK, "admin ok"); err != nil {
		return fmt.Errorf("expired ban remained active: %w", err)
	}
	response, err = public.Get(strings.TrimRight(origin, "/") + "/v1/snapshot")
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("private Caddy security route was exposed publicly with status %d", response.StatusCode)
	}
	fmt.Println("Caddy dynamic admin ban, HTTP 403, unban, expiry, request aggregation, private control, and Jellyfin-route isolation passed")
	return nil
}
