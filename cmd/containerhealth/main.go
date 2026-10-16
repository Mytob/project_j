package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Mytob/project_j/internal/containerhealth"
)

func main() {
	listen := flag.String("listen", ":8282", "private HTTP listen address")
	socket := flag.String("docker-socket", "/var/run/docker.sock", "read-only observation access to the Docker Engine socket")
	flag.Parse()
	server := &http.Server{Addr: *listen, Handler: containerhealth.New(*socket).Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 6 * time.Second, WriteTimeout: 6 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8 << 10}
	slog.Info("private container health observer listening", "address", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("container health observer stopped", "error", err)
		os.Exit(1)
	}
}
