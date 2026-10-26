package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/Mytob/project_j/internal/containerhealth"
)

type aboutResponse struct {
	Version             string                             `json:"version"`
	BuildID             string                             `json:"build_id"`
	InstalledAt         string                             `json:"installed_at,omitempty"`
	GoVersion           string                             `json:"go_version"`
	InventoryAvailable  bool                               `json:"inventory_available"`
	UbuntuVersion       string                             `json:"ubuntu_version,omitempty"`
	ProxyctlVersion     string                             `json:"proxyctl_version,omitempty"`
	DockerEngineVersion string                             `json:"docker_engine_version,omitempty"`
	ComposeVersion      string                             `json:"compose_version,omitempty"`
	Services            []containerhealth.ServiceInventory `json:"services"`
}

func (s *Server) apiAbout(w http.ResponseWriter, r *http.Request) {
	if _, authenticated := s.session(r); !authenticated {
		http.Error(w, "Administrator authentication required", http.StatusUnauthorized)
		return
	}
	value := aboutResponse{Version: s.version, BuildID: s.buildNumber, GoVersion: runtime.Version(), Services: []containerhealth.ServiceInventory{}}
	if s.installMetadataPath != "" {
		if data, err := readInstallMetadata(s.installMetadataPath); err == nil {
			value.InstalledAt = data
		}
	}
	if s.containerHealth != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		inventory, err := s.containerHealth.Inventory(ctx)
		cancel()
		if err == nil {
			value.InventoryAvailable = true
			value.UbuntuVersion = inventory.UbuntuVersion
			value.ProxyctlVersion = inventory.ProxyctlVersion
			value.DockerEngineVersion = inventory.DockerEngineVersion
			value.ComposeVersion = inventory.ComposeVersion
			value.Services = inventory.Services
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func readInstallMetadata(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 4096 {
		return "", os.ErrNotExist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var value struct {
		Version     int       `json:"version"`
		InstalledAt time.Time `json:"installed_at"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || decoder.Decode(new(any)) != io.EOF || value.Version != 1 || value.InstalledAt.IsZero() {
		return "", os.ErrInvalid
	}
	return value.InstalledAt.UTC().Format(time.RFC3339), nil
}
