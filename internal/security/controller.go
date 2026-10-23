package security

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SSHJail   = "jp-ssh"
	AdminJail = "jp-admin"
)

var (
	sshFailurePattern = regexp.MustCompile(`(?i)^Failed (?:password|publickey|keyboard-interactive(?:/pam)?|hostbased) for (?:invalid user )?\S+ from (\S+) port \d+(?:\s|$)`)
	sshSuccessPattern = regexp.MustCompile(`(?i)^Accepted (?:password|publickey|keyboard-interactive(?:/pam)?|hostbased) for \S+ from (\S+) port \d+(?:\s|$)`)
)

func ParseSSHAuthMessage(message string) (EventKind, string, bool) {
	matches := sshFailurePattern.FindStringSubmatch(strings.TrimSpace(message))
	kind := LoginFailure
	if len(matches) != 2 {
		matches = sshSuccessPattern.FindStringSubmatch(strings.TrimSpace(message))
		kind = LoginSuccess
	}
	if len(matches) != 2 {
		return "", "", false
	}
	address := strings.Trim(matches[1], "[]")
	ip, err := canonicalIP(address)
	if err != nil {
		return "", "", false
	}
	return kind, ip, true
}

// sshJournalMatchArgs covers both OpenSSH's long-standing sshd process name
// and the sshd-session name used by newer releases. journalctl treats the
// plus token as an OR between match groups.
func sshJournalMatchArgs() []string {
	return []string{"_COMM=sshd", "+", "_COMM=sshd-session"}
}

type commandRunner func(context.Context, string, ...string) (string, error)

type Fail2banClient struct {
	Path   string
	Socket string
	Now    func() time.Time
	run    commandRunner
}

func NewFail2banClient(path string) *Fail2banClient {
	return &Fail2banClient{Path: path, Socket: "/tmp/fail2ban.sock", run: runCommand}
}

func (f *Fail2banClient) command(ctx context.Context, args ...string) (string, error) {
	if f.Path == "" {
		return "", errors.New("fail2ban-client path is not configured")
	}
	runner := f.run
	if runner == nil {
		runner = runCommand
	}
	if f.Socket != "" {
		args = append([]string{"--socket", f.Socket}, args...)
	}
	return runner(ctx, f.Path, args...)
}

func (f *Fail2banClient) Ping(ctx context.Context) error {
	_, err := f.command(ctx, "ping")
	return err
}

func (f *Fail2banClient) JailStatus(ctx context.Context, jail string) error {
	_, err := f.command(ctx, "status", jail)
	return err
}

func (f *Fail2banClient) IsBanned(ctx context.Context, jail, ip string) (bool, error) {
	output, err := f.command(ctx, "get", jail, "banned", ip)
	if err != nil {
		return false, err
	}
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) == 0 {
		return false, errors.New("fail2ban returned an empty ban status")
	}
	return fields[len(fields)-1] == "1", nil
}

func (f *Fail2banClient) EnsureBan(ctx context.Context, ban Ban) error {
	jail := jailFor(ban.Service)
	banned, err := f.IsBanned(ctx, jail, ban.IP)
	if err != nil {
		return err
	}
	if banned {
		return nil
	}
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	remaining := ban.ExpiresAt.Sub(now())
	if remaining <= 0 {
		return nil
	}
	seconds := int64(remaining / time.Second)
	if remaining%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	if _, err := f.command(ctx, "set", jail, "bantime", strconv.FormatInt(seconds, 10)); err != nil {
		return err
	}
	_, err = f.command(ctx, "set", jail, "banip", ban.IP)
	return err
}

func (f *Fail2banClient) Unban(ctx context.Context, service Service, ip string) error {
	jail := jailFor(service)
	banned, err := f.IsBanned(ctx, jail, ip)
	if err != nil {
		return err
	}
	if !banned {
		return nil
	}
	_, err = f.command(ctx, "set", jail, "unbanip", ip)
	return err
}

func jailFor(service Service) string {
	if service == SSH {
		return SSHJail
	}
	return AdminJail
}

func runCommand(ctx context.Context, executable string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, executable, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s failed: %w (%s)", filepath.Base(executable), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

type Controller struct {
	Manager        *Manager
	EventsDir      string
	EventKey       []byte
	CaddySocket    string
	JournalCursor  string
	Fail2banClient *Fail2banClient
	Fail2banServer string
	Journalctl     string
	Nft            string
	Logger         *slog.Logger
	CaddyHTTP      *http.Client

	reconcileRequests chan struct{}
	enforcementMu     sync.Mutex
	mu                sync.RWMutex
	journalStatus     string
	journalError      string
	adminEventStatus  string
	adminEventError   string
	lastError         string
}

const (
	controllerMaintenanceInterval = time.Second
	controllerReconcileInterval   = 15 * time.Second
)

func NewController(manager *Manager, eventsDir string, eventKey []byte, caddySocket, cursorPath string, logger *slog.Logger) (*Controller, error) {
	if manager == nil || strings.TrimSpace(eventsDir) == "" || len(eventKey) < 32 || strings.TrimSpace(caddySocket) == "" || strings.TrimSpace(cursorPath) == "" {
		return nil, errors.New("manager, event spool, 256-bit event key, Caddy socket and journal cursor are required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	client, err := caddyHTTPClient(caddySocket)
	if err != nil {
		return nil, err
	}
	return &Controller{Manager: manager, EventsDir: eventsDir, EventKey: append([]byte(nil), eventKey...), CaddySocket: caddySocket, JournalCursor: cursorPath, Fail2banClient: NewFail2banClient("/usr/bin/fail2ban-client"), Fail2banServer: "/usr/bin/fail2ban-server", Journalctl: "/usr/bin/journalctl", Nft: "/usr/sbin/nft", Logger: logger, CaddyHTTP: client, reconcileRequests: make(chan struct{}, 1), journalStatus: "starting", adminEventStatus: "starting"}, nil
}

func (c *Controller) Run(ctx context.Context) error {
	go c.superviseFail2ban(ctx)
	go c.followSSHJournal(ctx)
	maintenanceTicker := time.NewTicker(controllerMaintenanceInterval)
	defer maintenanceTicker.Stop()
	reconcileTicker := time.NewTicker(controllerReconcileInterval)
	defer reconcileTicker.Stop()
	// Load any durable authentication events and establish the initial
	// enforcement and health snapshot before waiting for periodic recovery.
	c.processAdminSpool()
	c.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-maintenanceTicker.C:
			c.processAdminSpool()
			expired, err := c.Manager.Sweep()
			if err != nil {
				c.setError("persist ban expiration", err)
				continue
			}
			for _, event := range expired {
				if event.Service == SSH || event.Service == Admin {
					unbanCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
					err := c.Fail2banClient.Unban(unbanCtx, event.Service, event.IP)
					cancel()
					if err != nil {
						c.setError("expire fail2ban ticket", err)
					}
					if event.Service == Admin {
						c.requestReconcile()
					}
				}
			}
		case <-c.reconcileRequests:
			c.reconcile(ctx)
		case <-reconcileTicker.C:
			c.reconcile(ctx)
		}
	}
}

func (c *Controller) requestReconcile() {
	select {
	case c.reconcileRequests <- struct{}{}:
	default:
	}
}

func containsNewBan(events []HistoryEvent) bool {
	for _, event := range events {
		if event.Type == "ban" {
			return true
		}
	}
	return false
}

func (c *Controller) processAdminSpool() {
	items, rejected, err := ReadSpool(c.EventsDir, c.EventKey)
	if err != nil {
		c.setAdminEvent("degraded", err)
		c.setError("read administrator authentication events", err)
		return
	}
	if len(rejected) > 0 {
		directory := filepath.Join(c.EventsDir, "rejected")
		_ = os.MkdirAll(directory, 0o700)
		for _, item := range rejected {
			base := filepath.Base(item.Path)
			if err := os.Rename(item.Path, filepath.Join(directory, base)); err != nil {
				c.Logger.Error("quarantine invalid administrator event", "error", err)
			}
			c.setError("validate administrator authentication event", item.Err)
		}
		c.setAdminEvent("degraded", errors.New("one or more authentication events failed integrity validation"))
	}
	if len(items) == 0 {
		c.updateAdminEventHealth(len(rejected) == 0)
		return
	}
	events := make([]Event, 0, len(items))
	for _, item := range items {
		events = append(events, item.Event)
	}
	created, err := c.Manager.ApplyBatch(events)
	if err != nil {
		c.setAdminEvent("degraded", err)
		c.setError("process administrator authentication events", err)
		return
	}
	if containsNewBan(created) {
		c.requestReconcile()
	}
	for _, item := range items {
		if c.Manager.Processed(item.Event.ID) {
			if err := os.Remove(item.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				c.setError("remove processed authentication event", err)
			}
		}
	}
	c.updateAdminEventHealth(len(rejected) == 0)
}

func (c *Controller) updateAdminEventHealth(spoolHealthy bool) {
	if !spoolHealthy {
		return
	}
	if err := CheckEventWriterHealth(c.EventsDir, c.EventKey, time.Now().UTC(), 30*time.Second); err != nil {
		c.setAdminEvent("degraded", err)
		return
	}
	c.setAdminEvent("healthy", nil)
}

func (c *Controller) reconcile(ctx context.Context) {
	c.enforcementMu.Lock()
	defer c.enforcementMu.Unlock()
	snapshot := c.Manager.Snapshot()
	health := snapshot.Health
	// Health snapshots are rebuilt from current observations. Do not retain a
	// previous transient error after every component has recovered.
	health.LastError = ""
	c.mu.Lock()
	c.lastError = ""
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := c.Fail2banClient.Ping(ctx); err != nil {
		health.Fail2ban = "degraded"
		health.Firewall = "degraded"
		c.setError("connect to fail2ban", err)
	} else {
		health.Fail2ban = "healthy"
		sshErr := c.Fail2banClient.JailStatus(ctx, SSHJail)
		adminErr := c.Fail2banClient.JailStatus(ctx, AdminJail)
		if sshErr != nil || adminErr != nil {
			health.Fail2ban = "degraded"
			health.Firewall = "degraded"
			c.setError("inspect fail2ban jails", errors.Join(sshErr, adminErr))
		} else if rules, err := c.command(ctx, c.Nft, "list", "chain", "inet", "jp_fail2ban", "jp_ssh_input"); err != nil {
			health.Firewall = "degraded"
			c.setError("inspect SSH nftables enforcement chain", err)
		} else if !strings.Contains(rules, "tcp dport 22") {
			health.Firewall = "degraded"
			c.setError("inspect SSH nftables enforcement chain", errors.New("the Fail2ban chain does not contain a TCP port 22 drop rule"))
		} else {
			health.Firewall = "healthy"
			for _, ban := range snapshot.ActiveBans {
				if err := c.Fail2banClient.EnsureBan(ctx, ban); err != nil {
					health.Firewall = "degraded"
					c.setError("restore active fail2ban ban", err)
					break
				}
				active, err := c.Fail2banClient.IsBanned(ctx, jailFor(ban.Service), ban.IP)
				if err != nil || !active {
					health.Firewall = "degraded"
					if err == nil {
						err = errors.New("Fail2ban did not retain a persisted active ban")
					}
					c.setError("verify active fail2ban ban", err)
					break
				}
			}
		}
	}
	c.mu.RLock()
	health.SSHJournal = c.journalStatus
	if c.journalError != "" {
		health.LastError = c.journalError
	}
	if c.lastError != "" {
		health.LastError = c.lastError
	}
	c.mu.RUnlock()
	if health.SSHJournal != "healthy" {
		health.Firewall = "degraded"
	}
	c.mu.RLock()
	health.AdminEvents = c.adminEventStatus
	if c.adminEventError != "" {
		health.LastError = c.adminEventError
	}
	c.mu.RUnlock()
	counts, countErr := c.caddyBlocked(ctx)
	if countErr != nil {
		health.CaddySync = "degraded"
		health.LastError = "Caddy blocked-request counters are unavailable"
		c.setError("read Caddy blocked-request counters", countErr)
	} else if err := c.Manager.IngestBlockedCounts(counts, time.Now().UTC()); err != nil {
		health.CaddySync = "degraded"
		health.LastError = "Blocked-request totals could not be persisted"
		c.setError("persist Caddy blocked-request counters", err)
	} else if err := c.syncCaddy(ctx, snapshot.ActiveBans); err != nil {
		health.CaddySync = "degraded"
		health.LastError = "Caddy ban synchronization is unavailable"
		c.setError("synchronize Caddy admin bans", err)
	} else {
		health.CaddySync = "healthy"
	}
	if health.Fail2ban == "degraded" && health.LastError == "" {
		health.LastError = "Fail2ban is unavailable; existing administrator bans remain active in Caddy until expiry"
	}
	c.Manager.SetHealth(health)
}

func (c *Controller) Reconcile(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	c.enforcementMu.Lock()
	defer c.enforcementMu.Unlock()
	var result error
	if err := c.Fail2banClient.Ping(ctx); err != nil {
		result = errors.Join(result, err)
	} else {
		for _, ban := range c.Manager.Snapshot().ActiveBans {
			if err := c.Fail2banClient.EnsureBan(ctx, ban); err != nil {
				result = errors.Join(result, err)
			}
		}
	}
	if err := c.syncCaddy(ctx, c.Manager.Snapshot().ActiveBans); err != nil {
		result = errors.Join(result, err)
	}
	return result
}

func (c *Controller) CommitUnban(ctx context.Context, service Service, ip string, commit func() error) error {
	if commit == nil {
		return errors.New("unban transaction requires a state commit")
	}
	c.enforcementMu.Lock()
	defer c.enforcementMu.Unlock()

	snapshot := c.Manager.Snapshot()
	var enforcementErr error
	if service == SSH {
		enforcementErr = c.Fail2banClient.Unban(ctx, service, ip)
	} else if service == Admin {
		remaining := make([]Ban, 0, len(snapshot.ActiveBans))
		for _, ban := range snapshot.ActiveBans {
			if ban.Service == Admin && ban.IP == ip {
				continue
			}
			remaining = append(remaining, ban)
		}
		enforcementErr = c.syncCaddy(ctx, remaining)
	} else {
		return errors.New("service must be ssh or admin")
	}
	if enforcementErr != nil {
		return enforcementErr
	}
	if err := commit(); err != nil {
		var rollbackErr error
		if service == SSH {
			for _, ban := range snapshot.ActiveBans {
				if ban.Service == SSH && ban.IP == ip {
					rollbackErr = c.Fail2banClient.EnsureBan(ctx, ban)
					break
				}
			}
		} else {
			rollbackErr = c.syncCaddy(ctx, c.Manager.Snapshot().ActiveBans)
		}
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("commit unban: %w", err), fmt.Errorf("restore enforcement after failed unban: %w", rollbackErr))
		}
		return err
	}
	return nil
}

func (c *Controller) syncCaddy(ctx context.Context, bans []Ban) error {
	items := make([]struct {
		IP        string    `json:"ip"`
		ExpiresAt time.Time `json:"expires_at"`
	}, 0, len(bans))
	for _, ban := range bans {
		if ban.Service != Admin || !ban.ExpiresAt.After(time.Now()) {
			continue
		}
		items = append(items, struct {
			IP        string    `json:"ip"`
			ExpiresAt time.Time `json:"expires_at"`
		}{IP: ban.IP, ExpiresAt: ban.ExpiresAt})
	}
	body, err := json.Marshal(struct {
		Bans any `json:"bans"`
	}{Bans: items})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://caddy/v1/snapshot", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.CaddyHTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("Caddy security socket returned %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}

	statusRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://caddy/v1/status", nil)
	if err != nil {
		return err
	}
	statusResponse, err := c.CaddyHTTP.Do(statusRequest)
	if err != nil {
		return err
	}
	defer statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("Caddy security status returned %d", statusResponse.StatusCode)
	}
	var status struct {
		Synced     bool `json:"synced"`
		ActiveBans int  `json:"active_bans"`
	}
	if err := json.NewDecoder(io.LimitReader(statusResponse.Body, 4096)).Decode(&status); err != nil {
		return fmt.Errorf("decode Caddy security status: %w", err)
	}
	expected := 0
	for _, ban := range bans {
		if ban.Service == Admin && ban.ExpiresAt.After(time.Now()) {
			expected++
		}
	}
	if !status.Synced || status.ActiveBans != expected {
		return fmt.Errorf("Caddy ban blocklist reports %d active addresses; expected %d", status.ActiveBans, expected)
	}
	return nil
}

func (c *Controller) caddyBlocked(ctx context.Context) (map[string]uint64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://caddy/v1/blocked", nil)
	if err != nil {
		return nil, err
	}
	response, err := c.CaddyHTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Caddy blocked counter status %d", response.StatusCode)
	}
	var counts map[string]uint64
	err = json.NewDecoder(io.LimitReader(response.Body, 256<<10)).Decode(&counts)
	return counts, err
}

func caddyHTTPClient(socket string) (*http.Client, error) {
	if strings.TrimSpace(socket) == "" {
		return nil, errors.New("Caddy security socket path is empty")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &http.Client{Transport: transport}, nil
}

func (c *Controller) command(ctx context.Context, executable string, args ...string) (string, error) {
	return runCommand(ctx, executable, args...)
}

func (c *Controller) superviseFail2ban(ctx context.Context) {
	for ctx.Err() == nil {
		command := exec.CommandContext(ctx, c.Fail2banServer, "-xf", "--socket", "/tmp/fail2ban.sock", "--pidfile", "/tmp/fail2ban.pid", "--logtarget=stdout", "--loglevel=INFO", "start")
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Start(); err != nil {
			c.setError("start fail2ban server", err)
			if sleepContext(ctx, 3*time.Second) != nil {
				return
			}
			continue
		}
		if err := command.Wait(); ctx.Err() == nil {
			if err != nil {
				c.setError("fail2ban server stopped", err)
			} else {
				c.setError("fail2ban server stopped", errors.New("the process exited unexpectedly"))
			}
			if sleepContext(ctx, 3*time.Second) != nil {
				return
			}
		}
	}
}

type sshJournalRecord struct {
	Message        string `json:"MESSAGE"`
	Cursor         string `json:"__CURSOR"`
	Realtime       string `json:"__REALTIME_TIMESTAMP"`
	SourceRealtime string `json:"_SOURCE_REALTIME_TIMESTAMP"`
}

func (c *Controller) followSSHJournal(ctx context.Context) {
	for ctx.Err() == nil {
		cursor, _ := os.ReadFile(c.JournalCursor)
		args := []string{"--follow", "--no-pager", "--output=json", "--quiet"}
		if value := strings.TrimSpace(string(cursor)); value != "" {
			args = append(args, "--after-cursor="+value)
		} else {
			args = append(args, "--since=30 days ago")
		}
		args = append(args, sshJournalMatchArgs()...)
		command := exec.CommandContext(ctx, c.Journalctl, args...)
		stdout, err := command.StdoutPipe()
		if err != nil {
			c.setJournal("degraded", err)
			if sleepContext(ctx, 3*time.Second) != nil {
				return
			}
			continue
		}
		var stderr strings.Builder
		command.Stderr = &stderr
		if err := command.Start(); err != nil {
			c.setJournal("degraded", err)
			if sleepContext(ctx, 3*time.Second) != nil {
				return
			}
			continue
		}
		c.setJournal("healthy", nil)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 8192), 1<<20)
		for scanner.Scan() {
			var record sshJournalRecord
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				continue
			}
			if err := c.processSSHJournalRecord(record); err != nil {
				c.setJournal("degraded", err)
				break
			}
		}
		scanErr := scanner.Err()
		waitErr := command.Wait()
		if ctx.Err() != nil {
			return
		}
		if scanErr != nil {
			c.setJournal("degraded", scanErr)
		} else if waitErr != nil {
			message := strings.TrimSpace(stderr.String())
			if message == "" {
				c.setJournal("degraded", waitErr)
			} else {
				c.setJournal("degraded", fmt.Errorf("%s: %w", message, waitErr))
			}
		}
		// Replaying the 30-day journal window is safe: cursor-derived IDs make
		// already processed records idempotent after journal rotation or restart.
		_ = os.Remove(c.JournalCursor)
		if sleepContext(ctx, 2*time.Second) != nil {
			return
		}
	}
}

func (c *Controller) processSSHJournalRecord(record sshJournalRecord) error {
	kind, ip, ok := ParseSSHAuthMessage(record.Message)
	if !ok {
		if record.Cursor != "" {
			return c.writeCursor(record.Cursor)
		}
		return nil
	}
	timestamp := record.Realtime
	if timestamp == "" {
		timestamp = record.SourceRealtime
	}
	micros, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("SSH journal entry has no parseable source timestamp")
	}
	at := time.UnixMicro(micros).UTC()
	if record.Cursor == "" {
		return errors.New("SSH journal entry has no durable cursor")
	}
	identifier := sha256.Sum256([]byte(record.Cursor))
	event := Event{ID: "ssh:" + hex.EncodeToString(identifier[:]), Service: SSH, Kind: kind, IP: ip, At: at}
	created, err := c.Manager.Apply(event)
	if err != nil {
		if c.Manager.Processed(event.ID) {
			return c.writeCursor(record.Cursor)
		}
		return err
	}
	if containsNewBan(created) {
		c.requestReconcile()
	}
	return c.writeCursor(record.Cursor)
}

func (c *Controller) writeCursor(cursor string) error {
	if cursor == "" {
		return errors.New("journal cursor is empty")
	}
	if err := os.MkdirAll(filepath.Dir(c.JournalCursor), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(c.JournalCursor), ".ssh-cursor-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := io.WriteString(temporary, cursor); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, c.JournalCursor)
}

func (c *Controller) setJournal(state string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.journalStatus = state
	if err != nil {
		c.journalError = err.Error()
	} else {
		c.journalError = ""
	}
}

func (c *Controller) setAdminEvent(state string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.adminEventStatus = state
	if err != nil {
		c.adminEventError = err.Error()
	} else {
		c.adminEventError = ""
	}
}

func (c *Controller) setError(action string, err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	c.lastError = action + ": " + err.Error()
	c.mu.Unlock()
	c.Logger.Error(action, "error", err)
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
