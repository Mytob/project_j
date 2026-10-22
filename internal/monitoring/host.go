package monitoring

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostMetrics contains measurements from the Linux host. Missing values are
// represented by nil so consumers cannot mistake an unavailable measurement
// for a real zero.
type HostMetrics struct {
	CapturedAt       time.Time `json:"captured_at"`
	CPUPercent       *float64  `json:"cpu_percent,omitempty"`
	MemoryUsedBytes  *uint64   `json:"memory_used_bytes,omitempty"`
	MemoryTotalBytes *uint64   `json:"memory_total_bytes,omitempty"`
	MemoryAvailable  *uint64   `json:"memory_available_bytes,omitempty"`
	SwapUsedBytes    *uint64   `json:"swap_used_bytes,omitempty"`
	SwapTotalBytes   *uint64   `json:"swap_total_bytes,omitempty"`
	DiskUsedBytes    *uint64   `json:"disk_used_bytes,omitempty"`
	DiskFreeBytes    *uint64   `json:"disk_free_bytes,omitempty"`
	DiskTotalBytes   *uint64   `json:"disk_total_bytes,omitempty"`
	NetworkInBPS     *uint64   `json:"network_in_bytes_per_second,omitempty"`
	NetworkOutBPS    *uint64   `json:"network_out_bytes_per_second,omitempty"`
	NetworkInTotal   *uint64   `json:"network_in_total_bytes,omitempty"`
	NetworkOutTotal  *uint64   `json:"network_out_total_bytes,omitempty"`
	Load1            *float64  `json:"load_1,omitempty"`
	Load5            *float64  `json:"load_5,omitempty"`
	Load15           *float64  `json:"load_15,omitempty"`
	UptimeSeconds    *uint64   `json:"uptime_seconds,omitempty"`
}

// HostCollector reads only explicitly configured, read-only host mounts.
// ProcRoot should contain host /proc; SysRoot host /sys; RootFS the host root
// filesystem bind mount used for capacity measurements.
type HostCollector struct {
	ProcRoot string
	SysRoot  string
	RootFS   string
	now      func() time.Time
	mu       sync.Mutex
	previous *hostSnapshot
}

type hostSnapshot struct {
	at             time.Time
	cpuTotal       uint64
	cpuIdle        uint64
	cpuAvailable   bool
	netIn          uint64
	netOut         uint64
	networkAvailable bool
}

func NewHostCollector(procRoot, sysRoot, rootFS string) *HostCollector {
	return &HostCollector{ProcRoot: procRoot, SysRoot: sysRoot, RootFS: rootFS, now: time.Now}
}

func (c *HostCollector) Collect() HostMetrics {
	at := c.now().UTC()
	result := HostMetrics{CapturedAt: at}
	root := c.ProcRoot
	if root == "" {
		root = "/host/proc"
	}
	var cpuTotal, cpuIdle uint64
	cpuAvailable := false
	if total, idle, err := readCPU(filepath.Join(root, "stat")); err == nil {
		cpuTotal, cpuIdle = total, idle
		cpuAvailable = true
	}
	if mem, err := readMemInfo(filepath.Join(root, "meminfo")); err == nil {
		if total, okTotal := mem["MemTotal"]; okTotal {
			if available, okAvailable := mem["MemAvailable"]; okAvailable && available <= total {
				result.MemoryTotalBytes = u64(total)
				result.MemoryAvailable = u64(available)
				result.MemoryUsedBytes = u64(total - available)
			}
		}
		if total, okTotal := mem["SwapTotal"]; okTotal {
			if free, okFree := mem["SwapFree"]; okFree && free <= total {
				result.SwapTotalBytes = u64(total)
				result.SwapUsedBytes = u64(total - free)
			}
		}
	}
	if used, free, total, err := diskUsage(c.RootFS); err == nil {
		result.DiskUsedBytes, result.DiskFreeBytes, result.DiskTotalBytes = u64(used), u64(free), u64(total)
	}
	if one, five, fifteen, err := readLoad(filepath.Join(root, "loadavg")); err == nil {
		result.Load1, result.Load5, result.Load15 = f64(one), f64(five), f64(fifteen)
	}
	if uptime, err := readUptime(filepath.Join(root, "uptime")); err == nil {
		result.UptimeSeconds = u64(uptime)
	}

	var rx, tx uint64
	networkAvailable := false
	procNet := filepath.Join(root, "1", "net", "dev")
	if c.SysRoot != "" {
		if in, out, err := readHostNetwork(procNet, filepath.Join(c.SysRoot, "class", "net")); err == nil {
			rx, tx = in, out
			networkAvailable = true
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.previous != nil {
		elapsed := at.Sub(c.previous.at).Seconds()
		if elapsed > 0 && cpuAvailable && c.previous.cpuAvailable && cpuTotal >= c.previous.cpuTotal && cpuIdle >= c.previous.cpuIdle {
			totalDelta := cpuTotal - c.previous.cpuTotal
			idleDelta := cpuIdle - c.previous.cpuIdle
			if totalDelta > 0 && idleDelta <= totalDelta {
				result.CPUPercent = f64(float64(totalDelta-idleDelta) * 100 / float64(totalDelta))
			}
		}
		if elapsed > 0 && networkAvailable && c.previous.networkAvailable && rx >= c.previous.netIn && tx >= c.previous.netOut {
			result.NetworkInBPS = u64(uint64(float64(rx-c.previous.netIn) / elapsed))
			result.NetworkOutBPS = u64(uint64(float64(tx-c.previous.netOut) / elapsed))
		}
	}
	if networkAvailable {
		result.NetworkInTotal, result.NetworkOutTotal = u64(rx), u64(tx)
	}
	c.previous = &hostSnapshot{at: at, cpuTotal: cpuTotal, cpuIdle: cpuIdle, cpuAvailable: cpuAvailable, netIn: rx, netOut: tx, networkAvailable: networkAvailable}
	return result
}

func u64(value uint64) *uint64   { return &value }
func f64(value float64) *float64 { return &value }

func readCPU(path string) (total, idle uint64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != "cpu" {
			continue
		}
		if len(fields) < 5 {
			return 0, 0, errors.New("host CPU counters are incomplete")
		}
		var values []uint64
		for _, field := range fields[1:] {
			value, parseErr := strconv.ParseUint(field, 10, 64)
			if parseErr != nil {
				return 0, 0, errors.New("host CPU counter is invalid")
			}
			values = append(values, value)
		}
		// Linux reports guest and guest_nice again as part of user and nice.
		// Include user through steal (the first eight counters) only, otherwise
		// guest time is counted twice and CPU utilization is understated.
		limit := len(values)
		if limit > 8 {
			limit = 8
		}
		for _, value := range values[:limit] {
			total += value
		}
		idle = values[3]
		if len(values) > 4 {
			idle += values[4] // Linux iowait is idle time for utilization.
		}
		return total, idle, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return 0, 0, errors.New("host CPU counters are missing")
}

func readMemInfo(path string) (map[string]uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	values := make(map[string]uint64, 16)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid %s value in host meminfo", name)
		}
		if len(fields) >= 3 && fields[2] == "kB" {
			if value > ^uint64(0)/1024 {
				return nil, errors.New("host memory value overflows bytes")
			}
			value *= 1024
		}
		values[name] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func readLoad(path string) (float64, float64, float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, errors.New("host load averages are incomplete")
	}
	values := [3]float64{}
	for i := range values {
		values[i], err = strconv.ParseFloat(fields[i], 64)
		if err != nil || values[i] < 0 {
			return 0, 0, 0, errors.New("host load average is invalid")
		}
	}
	return values[0], values[1], values[2], nil
}

func readUptime(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errors.New("host uptime is empty")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0, errors.New("host uptime is invalid")
	}
	return uint64(seconds), nil
}

func readHostNetwork(procDevPath, sysNetPath string) (uint64, uint64, error) {
	file, err := os.Open(procDevPath)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	var received, transmitted uint64
	found := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if !isPhysicalInterface(name, sysNetPath) {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			return 0, 0, errors.New("host network counters are incomplete")
		}
		rx, parseErr := strconv.ParseUint(fields[0], 10, 64)
		if parseErr != nil {
			return 0, 0, errors.New("host receive counter is invalid")
		}
		tx, parseErr := strconv.ParseUint(fields[8], 10, 64)
		if parseErr != nil {
			return 0, 0, errors.New("host transmit counter is invalid")
		}
		if ^uint64(0)-received < rx || ^uint64(0)-transmitted < tx {
			return 0, 0, errors.New("host network counter sum overflows")
		}
		received += rx
		transmitted += tx
		found++
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if found == 0 {
		return 0, 0, errors.New("no physical host network interfaces were found")
	}
	return received, transmitted, nil
}

func isPhysicalInterface(name, sysNetPath string) bool {
	if name == "" || name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "tailscale") {
		return false
	}
	_, err := os.Stat(filepath.Join(sysNetPath, name, "device"))
	return err == nil
}
