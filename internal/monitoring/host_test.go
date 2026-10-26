package monitoring

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestReadCPUIncludesIOWaitAsIdle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(path, []byte("cpu 100 10 20 300 30 2 3 4 50 70\ncpu0 1 0 1 3 0 0 0 0 5 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	total, idle, err := readCPU(path)
	if err != nil {
		t.Fatal(err)
	}
	if total != 469 || idle != 330 {
		t.Fatalf("readCPU() = total %d idle %d, want 469 and 330 (guest counters excluded)", total, idle)
	}
}

func TestReadMemInfoConvertsUnitsAndRejectsOverflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meminfo")
	if err := os.WriteFile(path, []byte("MemTotal: 8 kB\nMemAvailable: 3 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := readMemInfo(path)
	if err != nil || values["MemTotal"] != 8192 || values["MemAvailable"] != 3072 {
		t.Fatalf("readMemInfo() = %#v, %v", values, err)
	}
	if err := os.WriteFile(path, []byte("MemTotal: 18446744073709551615 kB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMemInfo(path); err == nil {
		t.Fatal("overflowing host memory value was accepted")
	}
}

func TestReadHostNetworkSumsOnlyPhysicalDeviceCounters(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "sys", "class", "net")
	for _, name := range []string{"enp1s0", "docker0", "vethabcd"} {
		path := filepath.Join(sys, name, "device")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	proc := filepath.Join(root, "dev")
	body := "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n" +
		" enp1s0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0\n" +
		" docker0: 9000 1 0 0 0 0 0 0 8000 1 0 0 0 0 0 0\n" +
		" vethabcd: 7000 1 0 0 0 0 0 0 6000 1 0 0 0 0 0 0\n" +
		" lo: 9999 1 0 0 0 0 0 0 9999 1 0 0 0 0 0 0\n"
	if err := os.WriteFile(proc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	in, out, err := readHostNetwork(proc, sys)
	if err != nil || in != 1000 || out != 2000 {
		t.Fatalf("readHostNetwork() = %d, %d, %v; want 1000, 2000", in, out, err)
	}
}

func TestHostCollectorComputesRatesAndResets(t *testing.T) {
	proc, sys, rootFS := writeHostFixture(t, 1000, 2000)
	c := NewHostCollector(proc, sys, rootFS)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return clock }
	first := c.Collect()
	if first.CPUPercent != nil || first.NetworkInBPS != nil || first.MemoryUsedBytes == nil || *first.MemoryUsedBytes != 5*1024 {
		t.Fatalf("first measurement has incorrect availability or memory values: %+v", first)
	}
	writeFixtureCounters(t, proc, 1100, 950, 1600, 2400)
	clock = clock.Add(time.Second)
	second := c.Collect()
	if second.CPUPercent == nil || *second.CPUPercent != 50 || second.NetworkInBPS == nil || *second.NetworkInBPS != 600 || second.NetworkOutBPS == nil || *second.NetworkOutBPS != 400 {
		t.Fatalf("second measurement rates = CPU %v in %v out %v", second.CPUPercent, second.NetworkInBPS, second.NetworkOutBPS)
	}
	writeFixtureCounters(t, proc, 50, 25, 10, 20)
	clock = clock.Add(time.Second)
	reset := c.Collect()
	if reset.CPUPercent != nil || reset.NetworkInBPS != nil || reset.NetworkOutBPS != nil {
		t.Fatalf("counter reset should make one rate sample unavailable: %+v", reset)
	}
}

func TestCollectorReportsUnavailableHostMetricsAsMissing(t *testing.T) {
	c := NewHostCollector(filepath.Join(t.TempDir(), "missing"), "", "")
	metrics := c.Collect()
	if metrics.CPUPercent != nil || metrics.MemoryTotalBytes != nil || metrics.NetworkInTotal != nil || metrics.DiskTotalBytes != nil {
		t.Fatalf("missing host data was reported as measured zero: %+v", metrics)
	}
}

func writeHostFixture(t *testing.T, rx, tx uint64) (proc, sys, root string) {
	t.Helper()
	base := t.TempDir()
	proc = filepath.Join(base, "proc")
	sys = filepath.Join(base, "sys", "class", "net")
	root = filepath.Join(base, "root")
	if err := os.MkdirAll(filepath.Join(proc, "1", "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sys, "eth0"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sys, "eth0", "device"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "meminfo"), []byte("MemTotal: 10 kB\nMemAvailable: 5 kB\nSwapTotal: 2 kB\nSwapFree: 1 kB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "loadavg"), []byte("0.10 0.20 0.30 1/10 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "uptime"), []byte("3600.50 100.00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeFixtureCounters(t, proc, 1000, 900, rx, tx)
	return proc, filepath.Join(base, "sys"), root
}

func writeFixtureCounters(t *testing.T, proc string, cpuTotal, cpuIdle, rx, tx uint64) {
	t.Helper()
	stat := "cpu " + strconv.FormatUint(cpuTotal-cpuIdle, 10) + " 0 0 " + strconv.FormatUint(cpuIdle, 10) + " 0 0 0 0 0 0\n"
	net := "eth0: " + strconv.FormatUint(rx, 10) + " 0 0 0 0 0 0 0 " + strconv.FormatUint(tx, 10) + " 0 0 0 0 0 0 0\n"
	if err := os.WriteFile(filepath.Join(proc, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "1", "net", "dev"), []byte(net), 0o600); err != nil {
		t.Fatal(err)
	}
}
