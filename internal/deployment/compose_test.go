package deployment

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestProductionComposeDoesNotExposeDockerSocketToContainers(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]struct {
			Volumes  []any    `yaml:"volumes"`
			Command  []string `yaml:"command"`
			GroupAdd []string `yaml:"group_add"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatal(err)
	}
	if _, exists := compose.Services["containerhealth"]; exists {
		t.Fatal("production Compose must not run a Docker-socket-backed observer container")
	}
	admin, exists := compose.Services["admin"]
	if !exists {
		t.Fatal("production admin service is missing")
	}
	if !containsString(admin.Command, "--container-health-socket") || !containsString(admin.Command, "/run/jp-maintenance/maintenance.sock") {
		t.Fatalf("admin service is not configured for the restricted maintenance API: %v", admin.Command)
	}
	if !containsString(admin.GroupAdd, "65532") {
		t.Fatalf("admin service lacks its maintenance socket group: %v", admin.GroupAdd)
	}
	maintenanceMount := false
	for _, raw := range admin.Volumes {
		mount, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if mount["source"] == "/var/run/docker.sock" {
			t.Fatal("admin service must never mount the Docker API socket")
		}
		if mount["source"] == "/run/jellyfin-proxy-maintenance" && mount["target"] == "/run/jp-maintenance" && mount["read_only"] == true {
			maintenanceMount = true
		}
	}
	if !maintenanceMount {
		t.Fatal("admin must receive only the read-only maintenance API socket directory")
	}
}

func TestSecuritydMountsHostMachineIDReadOnly(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]struct {
			Volumes     []any    `yaml:"volumes"`
			ReadOnly    bool     `yaml:"read_only"`
			CapDrop     []string `yaml:"cap_drop"`
			SecurityOpt []string `yaml:"security_opt"`
			Tmpfs       []string `yaml:"tmpfs"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse Compose file: %v", err)
	}
	securityd, ok := compose.Services["securityd"]
	if !ok {
		t.Fatal("securityd service is missing")
	}
	for _, raw := range securityd.Volumes {
		mount, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		source, _ := mount["source"].(string)
		target, _ := mount["target"].(string)
		readOnly, _ := mount["read_only"].(bool)
		if source == "/etc/machine-id" && target == "/etc/machine-id" && readOnly {
			return
		}
	}
	t.Fatal("securityd must mount the host machine-id read-only so journalctl can resolve the host journal")
}

func TestAdminServiceHasRestrictedRuntimeInBothComposeFiles(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "..", "deploy", "compose.yaml"),
		filepath.Join("..", "..", "tests", "integration", "compose.yaml"),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var compose struct {
			Services map[string]struct {
				ReadOnly    bool     `yaml:"read_only"`
				CapDrop     []string `yaml:"cap_drop"`
				SecurityOpt []string `yaml:"security_opt"`
				Tmpfs       []string `yaml:"tmpfs"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal(data, &compose); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		admin, ok := compose.Services["admin"]
		if !ok {
			t.Fatalf("admin service is missing from %s", path)
		}
		if !admin.ReadOnly || !containsString(admin.CapDrop, "ALL") || !containsString(admin.SecurityOpt, "no-new-privileges:true") || !containsString(admin.Tmpfs, "/tmp:size=16777216") {
			t.Errorf("admin runtime restrictions are incomplete in %s: %+v", path, admin)
		}
	}
}

func containsString(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}
