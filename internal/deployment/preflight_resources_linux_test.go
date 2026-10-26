//go:build linux

package deployment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadMemoryCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meminfo")
	if err := os.WriteFile(path, []byte("MemTotal:       8192000 kB\nMemFree:        1024 kB\nMemAvailable:   4096000 kB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	total, available, err := readMemoryCapacity(path)
	if err != nil || total != 8192000*1024 || available != 4096000*1024 {
		t.Fatalf("memory capacity = total %d, available %d, err %v", total, available, err)
	}
	if err := os.WriteFile(path, []byte("MemTotal: 1024 kB\nMemAvailable: 2048 kB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readMemoryCapacity(path); err == nil {
		t.Fatal("accepted available memory greater than total memory")
	}
}

func TestInstallResourceReportSurfacesLowCapacityAndKernelStatus(t *testing.T) {
	report := InstallResourceReport{
		MemoryTotalBytes:          2 << 30,
		MemoryAvailableBytes:      512 << 20,
		InstallDiskAvailableBytes: 1 << 30,
		DockerDiskAvailableBytes:  1 << 30,
		WireGuardKernelAvailable:  true,
	}
	warnings := report.Warnings()
	if len(warnings) != 2 {
		t.Fatalf("resource warnings = %v, want memory and disk warnings", warnings)
	}
	if got := report.Summary(); !strings.Contains(got, "memory available") || !strings.Contains(strings.Join(warnings, "; "), "available memory is below the 1 GiB recommendation") || !strings.Contains(strings.Join(warnings, "; "), "free disk space is below the 2 GiB recommendation") {
		t.Fatalf("resource summary/warnings were not actionable: %q %v", got, warnings)
	}
}

func TestAvailableBytesUsesNearestExistingMountDirectory(t *testing.T) {
	root := t.TempDir()
	available, err := availableBytes(filepath.Join(root, "not-created", "docker"))
	if err != nil || available == 0 {
		t.Fatalf("available bytes for not-yet-created data directory = %d, %v", available, err)
	}
}
