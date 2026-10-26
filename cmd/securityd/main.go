package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Mytob/project_j/internal/security"
)

func main() {
	healthCheck := flag.Bool("healthcheck", false, "exit successfully only when all security protections are enforced and observable")
	statePath := flag.String("state", "/var/lib/jellyfin-proxy/security/state.json", "persistent ban and policy state")
	eventsDir := flag.String("events", "/var/lib/jellyfin-proxy/security-events", "signed administrator event spool")
	eventKeyPath := flag.String("event-key", "/run/jellyfin-proxy-security/event.key", "HMAC key shared with the admin backend")
	controlSocket := flag.String("control-socket", "/run/jellyfin-proxy-security/control.sock", "private control socket shared with the admin backend")
	caddySocket := flag.String("caddy-socket", "/run/caddy-security/control.sock", "private control socket shared with Caddy")
	cursorPath := flag.String("journal-cursor", "/var/lib/jellyfin-proxy/security/ssh.cursor", "durable systemd journal cursor")
	journalctlPath := flag.String("journalctl", "/usr/bin/journalctl", "read-only systemd journal reader")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if *healthCheck {
		client, err := security.NewClient(*controlSocket)
		if err != nil {
			logger.Error("configure security health check", "error", err)
			os.Exit(1)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		snapshot, err := client.Snapshot(ctx)
		cancel()
		if err != nil {
			logger.Error("security control socket is unavailable", "error", err)
			os.Exit(1)
		}
		health := snapshot.Health
		if health.Fail2ban != "healthy" || health.SSHJournal != "healthy" || health.Firewall != "healthy" || health.AdminEvents != "healthy" || health.CaddySync != "healthy" {
			logger.Error("security protections are not fully healthy", "fail2ban", health.Fail2ban, "ssh_journal", health.SSHJournal, "firewall", health.Firewall, "admin_events", health.AdminEvents, "caddy_sync", health.CaddySync)
			os.Exit(1)
		}
		return
	}
	key, err := os.ReadFile(*eventKeyPath)
	if err != nil {
		logger.Error("read administrator authentication event key", "error", err)
		os.Exit(1)
	}
	if len(key) < 32 {
		clear(key)
		logger.Error("administrator authentication event key must contain at least 256 bits")
		os.Exit(1)
	}
	defer clear(key)
	manager, err := security.Open(*statePath, time.Now)
	if err != nil {
		logger.Error("open persistent security state", "error", err)
		os.Exit(1)
	}
	controller, err := security.NewController(manager, *eventsDir, key, *caddySocket, *cursorPath, logger)
	if err != nil {
		logger.Error("configure security controller", "error", err)
		os.Exit(1)
	}
	controller.Journalctl = *journalctlPath
	api := &security.ControlAPI{Manager: manager, OnChange: controller.Reconcile, OnUnban: controller.CommitUnban}
	listener, err := listenControlSocket(*controlSocket)
	if err != nil {
		logger.Error("open private security control socket", "error", err)
		os.Exit(1)
	}
	defer listener.Close()
	server := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		if err := controller.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("run security controller", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	logger.Info("security control service started", "socket", *controlSocket)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serve private security API", "error", err)
		os.Exit(1)
	}
}

func listenControlSocket(path string) (net.Listener, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("security control socket path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("refusing to replace a non-socket security control path")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, 0, 65532); err != nil {
		listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return listener, nil
}
