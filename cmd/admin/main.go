package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Mytob/project_j/internal/admin"
	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/whitelist"
)

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	config := flag.String("config", "/opt/jellyfin-proxy/config/admin.json", "administrator credential file")
	totpKey := flag.String("totp-key", "/opt/jellyfin-proxy/config/totp.key", "administrator TOTP storage key file")
	totpState := flag.String("totp-state", "/opt/jellyfin-proxy/data/totp-state.json", "administrator TOTP state file")
	whitelistPath := flag.String("whitelist", "/opt/jellyfin-proxy/data/whitelist.json", "persistent whitelist file")
	caddySocket := flag.String("caddy-socket", "/run/caddy-admin/admin.sock", "private Caddy admin Unix socket")
	caddyfile := flag.String("caddyfile", "/etc/caddy/Caddyfile", "Caddyfile template containing the whitelist import")
	wireguardConfig := flag.String("wireguard-client-config", "/opt/jellyfin-proxy/config/wireguard/windows.conf", "retained Windows WireGuard peer configuration")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	credential, err := auth.LoadCredential(*config)
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
	manager := admin.NewWhitelistManager(store, admin.NewCaddyAPI(*caddySocket, *caddyfile))
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
	if err := application.ConfigureTOTPStore(totpStore); err != nil {
		logger.Error("configure administrator TOTP", "error", err)
		os.Exit(1)
	}
	if err := application.ConfigureWireGuardConfig(*wireguardConfig); err != nil {
		logger.Error("configure Windows WireGuard download", "error", err)
		os.Exit(1)
	}
	server := &http.Server{Addr: *listen, Handler: application.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	logger.Info("admin server listening", "address", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("admin server stopped", "error", err)
		os.Exit(1)
	}
}
