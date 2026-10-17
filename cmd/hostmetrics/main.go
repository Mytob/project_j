package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Mytob/project_j/internal/monitoring"
)

func main() {
	listen := flag.String("listen", ":8181", "private metrics listener")
	procRoot := flag.String("proc", "/host/proc", "read-only host proc mount")
	sysRoot := flag.String("sys", "/host/sys", "read-only host sys mount")
	rootFS := flag.String("rootfs", "/host/root", "read-only host root filesystem mount")
	flag.Parse()

	collector := monitoring.NewHostCollector(*procRoot, *sysRoot, *rootFS)
	var mu sync.RWMutex
	latest := collector.Collect()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				next := collector.Collect()
				mu.Lock()
				latest = next
				mu.Unlock()
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		metrics := latest
		mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(metrics); err != nil {
			log.Printf("encode host metrics: %v", err)
		}
	})
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 15 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("host metrics collector listening on private address %s", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
