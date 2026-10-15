package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Mytob/project_j/internal/admin"
	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/whitelist"
)

var version = "development"
var buildNumber = "unknown"

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	config := flag.String("config", "/opt/jellyfin-proxy/config/admin.json", "administrator credential file")
	credentialOverride := flag.String("credential-override", "/opt/jellyfin-proxy/data/admin-credential.json", "mutable administrator credential file, when present")
	healthState := flag.String("health-state", "/opt/jellyfin-proxy/data/health-state.json", "persistent administrator health history")
	totpKey := flag.String("totp-key", "/opt/jellyfin-proxy/config/totp.key", "administrator TOTP storage key file")
	totpState := flag.String("totp-state", "/opt/jellyfin-proxy/data/totp-state.json", "administrator TOTP state file")
	whitelistPath := flag.String("whitelist", "/opt/jellyfin-proxy/data/whitelist.json", "persistent whitelist file")
	caddySocket := flag.String("caddy-socket", "/run/caddy-admin/admin.sock", "private Caddy admin Unix socket")
	caddyfile := flag.String("caddyfile", "/etc/caddy/Caddyfile", "Caddyfile template containing the whitelist import")
	wireguardConfig := flag.String("wireguard-client-config", "/opt/jellyfin-proxy/data/wireguard-client/windows.conf", "one-time Windows WireGuard peer configuration")
	wireguardControl := flag.String("wireguard-control-socket", "/run/wireguard-control/control.sock", "private WireGuard control socket")
	wireguardEndpoint := flag.String("wireguard-endpoint", os.Getenv("WIREGUARD_ENDPOINT"), "public WireGuard client endpoint")
	wireguardKeepalive := flag.Uint("wireguard-keepalive", 25, "Windows peer persistent keepalive in seconds")
	wireguardHealth := flag.String("wireguard-health", "/run/wireguard-health/current", "read-only recent WireGuard interface health heartbeat")
	hostMetricsURL := flag.String("host-metrics-url", "http://hostmetrics:8181", "private host metrics collector origin")
	proxyMetricsPath := flag.String("proxy-metrics", "/run/proxy-metrics/current.json", "read-only current Caddy metrics snapshot")
	statisticsPath := flag.String("statistics-history", "/opt/jellyfin-proxy/data/statistics", "persistent 90-day statistics directory")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	credentialPath := *config
	if info, statErr := os.Lstat(*credentialOverride); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			logger.Error("administrator credential override must be a regular file")
			os.Exit(1)
		}
		credentialPath = *credentialOverride
	} else if !errors.Is(statErr, os.ErrNotExist) {
		logger.Error("inspect administrator credential override", "error", statErr)
		os.Exit(1)
	}
	credential, err := auth.LoadCredential(credentialPath)
	if err != nil {
		logger.Error("load administrator credential", "error", err)
		os.Exit(1)
	}
	key, err := auth.LoadTOTPKey(*totpKey)
	if err != nil {
		logger.Error("load administrator TOTP key", "error", err)
		os.Exit(1)
	}
	totpStore, err := auth.NewTOTPStore(*totpState, key)
	clear(key)
	if err != nil {
		logger.Error("load administrator TOTP state", "error", err)
		os.Exit(1)
	}
	store, err := whitelist.NewStore(*whitelistPath)
	if err != nil {
		logger.Error("configure whitelist store", "error", err)
		os.Exit(1)
	}
	caddyAPI := admin.NewCaddyAPI(*caddySocket, *caddyfile)
	manager := admin.NewWhitelistManager(store, caddyAPI)
	var initializeErr error
	for attempt := 0; attempt < 60; attempt++ {
		initializeErr = manager.Initialize()
		if initializeErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if initializeErr != nil {
		logger.Error("initialize whitelist", "error", initializeErr)
		os.Exit(1)
	}
	application := admin.New(credential, logger, manager)
	if err := application.ConfigureCredentialPath(*credentialOverride); err != nil {
		logger.Error("configure administrator credential changes", "error", err)
		os.Exit(1)
	}
	if err := application.ConfigureHealthState(*healthState); err != nil {
		logger.Error("configure administrator health history", "error", err)
		os.Exit(1)
	}
	application.ConfigureComponentHealth(caddyAPI, *wireguardHealth)
	application.ConfigureBuildInfo(version, buildNumber)
	if err := application.ConfigureTOTPStore(totpStore); err != nil {
		logger.Error("configure administrator TOTP", "error", err)
		os.Exit(1)
	}
	if err := application.ConfigureWireGuardConfig(*wireguardConfig); err != nil {
		logger.Error("configure Windows WireGuard download", "error", err)
		os.Exit(1)
	}
	if *wireguardKeepalive > 65535 {
		logger.Error("WireGuard keepalive is out of range")
		os.Exit(1)
	}
	if err := application.ConfigureWireGuardControl(*wireguardControl, *wireguardEndpoint, uint16(*wireguardKeepalive)); err != nil {
		logger.Error("configure private WireGuard peer control", "error", err)
		os.Exit(1)
	}
	history, historyErr := monitoring.OpenHistory(*statisticsPath)
	if historyErr != nil {
		logger.Warn("statistics history is unavailable", "error", historyErr)
	} else if feed, feedErr := monitoring.NewFeed(*hostMetricsURL, *proxyMetricsPath, history, logger); feedErr != nil {
		logger.Warn("live statistics are unavailable", "error", feedErr)
	} else {
		if err := application.ConfigureStatistics(feed); err != nil {
			logger.Warn("statistics page is unavailable", "error", err)
		} else {
			go feed.Start(context.Background())
		}
	}
	server := &http.Server{Addr: *listen, Handler: application.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	logger.Info("admin server listening", "address", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("admin server stopped", "error", err)
		os.Exit(1)
	}
}
