//go:build linux

package deployment

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func InspectInstallResources(installRoot, dockerRoot string) (InstallResourceReport, error) {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	if dockerRoot == "" {
		dockerRoot = "/var/lib/docker"
	}
	var report InstallResourceReport
	var err error
	report.MemoryTotalBytes, report.MemoryAvailableBytes, err = readMemoryCapacity("/proc/meminfo")
	if err != nil {
		return report, fmt.Errorf("read available host memory: %w", err)
	}
	report.InstallDiskAvailableBytes, err = availableBytes(installRoot)
	if err != nil {
		return report, fmt.Errorf("inspect install filesystem: %w", err)
	}
	report.DockerDiskAvailableBytes, err = availableBytes(dockerRoot)
	if err != nil {
		return report, fmt.Errorf("inspect Docker filesystem: %w", err)
	}
	report.WireGuardKernelAvailable = wireGuardKernelAvailable()
	return report, nil
}

func readMemoryCapacity(path string) (total, available uint64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		var target *uint64
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			target = &total
		case "MemAvailable":
			target = &available
		default:
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return 0, 0, errors.New("memory capacity contains an invalid value")
		}
		if len(fields) >= 3 && fields[2] == "kB" {
			if value > ^uint64(0)/1024 {
				return 0, 0, errors.New("memory capacity value overflows")
			}
			value *= 1024
		}
		*target = value
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if total == 0 || available == 0 || available > total {
		return 0, 0, errors.New("memory capacity is incomplete")
	}
	return total, available, nil
}

func availableBytes(path string) (uint64, error) {
	path, err := existingDirectory(path)
	if err != nil {
		return 0, err
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 || uint64(stat.Bavail) > ^uint64(0)/uint64(stat.Bsize) {
		return 0, errors.New("filesystem capacity is invalid")
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), nil
}

func existingDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("filesystem path must be absolute")
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return "", errors.New("filesystem path is not a directory")
			}
			return current, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
	}
}

func wireGuardKernelAvailable() bool {
	if info, err := os.Stat("/sys/module/wireguard"); err == nil && info.IsDir() {
		return true
	}
	modprobe, err := exec.LookPath("modprobe")
	if err != nil {
		return false
	}
	return exec.Command(modprobe, "-n", "wireguard").Run() == nil
}
