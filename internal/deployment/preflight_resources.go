package deployment

import (
	"fmt"
)

const (
	installResourceWarningMemoryBytes = 1 << 30
	installResourceWarningDiskBytes   = 2 << 30
)

// InstallResourceReport records host capacity and the kernel capability used
// by the WireGuard container before installation changes the host.
type InstallResourceReport struct {
	MemoryTotalBytes          uint64
	MemoryAvailableBytes      uint64
	InstallDiskAvailableBytes uint64
	DockerDiskAvailableBytes  uint64
	WireGuardKernelAvailable  bool
}

func (r InstallResourceReport) Summary() string {
	wireGuard := "not available"
	if r.WireGuardKernelAvailable {
		wireGuard = "available"
	}
	summary := fmt.Sprintf("Preflight: memory available %s of %s; free space for /opt %s and Docker %s; WireGuard kernel support %s.", formatBytes(r.MemoryAvailableBytes), formatBytes(r.MemoryTotalBytes), formatBytes(r.InstallDiskAvailableBytes), formatBytes(r.DockerDiskAvailableBytes), wireGuard)
	if warnings := r.Warnings(); len(warnings) > 0 {
		summary += " Review: " + joinWarnings(warnings)
	}
	return summary
}

func (r InstallResourceReport) Warnings() []string {
	warnings := make([]string, 0, 2)
	if r.MemoryAvailableBytes < installResourceWarningMemoryBytes {
		warnings = append(warnings, "available memory is below the 1 GiB recommendation; install or enable swap before continuing if the host is memory constrained")
	}
	if r.InstallDiskAvailableBytes < installResourceWarningDiskBytes || r.DockerDiskAvailableBytes < installResourceWarningDiskBytes {
		warnings = append(warnings, "free disk space is below the 2 GiB recommendation; confirm that the selected filesystems can hold the application images and persistent data")
	}
	return warnings
}

func joinWarnings(values []string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += "; "
		}
		result += value
	}
	return result
}

func formatBytes(value uint64) string {
	if value == 0 {
		return "unknown"
	}
	const gib = uint64(1 << 30)
	if value >= gib {
		whole := value / gib
		tenths := (value % gib) * 10 / gib
		return fmt.Sprintf("%d.%d GiB", whole, tenths)
	}
	return fmt.Sprintf("%d MiB", value/(1<<20))
}
