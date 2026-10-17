package deployment

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestSecuritydMountsHostMachineIDReadOnly(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]struct {
			Volumes []any `yaml:"volumes"`
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
