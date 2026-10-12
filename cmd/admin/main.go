package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Mytob/project_j/internal/admin"
	"github.com/Mytob/project_j/internal/auth"
)

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	config := flag.String("config", "/opt/jellyfin-proxy/config/admin.json", "administrator credential file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	credential, err := auth.LoadCredential(*config)
	if err != nil {
		logger.Error("load administrator credential", "error", err)
		os.Exit(1)
	}
	server := &http.Server{Addr: *listen, Handler: admin.New(credential, logger).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	logger.Info("admin server listening", "address", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("admin server stopped", "error", err)
		os.Exit(1)
	}
}
