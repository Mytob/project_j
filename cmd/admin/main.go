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
	whitelistPath := flag.String("whitelist", "/opt/jellyfin-proxy/data/whitelist.json", "persistent whitelist file")
	caddySocket := flag.String("caddy-socket", "/run/caddy-admin/admin.sock", "private Caddy admin Unix socket")
	caddyfile := flag.String("caddyfile", "/etc/caddy/Caddyfile", "Caddyfile template containing the whitelist import")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	credential, err := auth.LoadCredential(*config)
	if err != nil {
		logger.Error("load administrator credential", "error", err)
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
	server := &http.Server{Addr: *listen, Handler: admin.New(credential, logger, manager).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	logger.Info("admin server listening", "address", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("admin server stopped", "error", err)
		os.Exit(1)
	}
}
