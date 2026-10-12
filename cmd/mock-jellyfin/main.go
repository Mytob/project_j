package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type publicInfo struct {
	ServerName  string `json:"ServerName"`
	ProductName string `json:"ProductName"`
	Version     string `json:"Version"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/System/Info/Public", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(publicInfo{
			ServerName:  "local-test-jellyfin",
			ProductName: "Jellyfin",
			Version:     "mock",
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "mock-jellyfin",
			"path":    r.URL.Path,
		})
	})

	server := &http.Server{
		Addr:              ":8096",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("mock Jellyfin listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
