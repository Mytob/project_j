package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestVersionCommandShowsBuildVersionBeforePrivilegeRecovery(t *testing.T) {
	prior := version
	version = "1.6.0-dev"
	t.Cleanup(func() { version = prior })
	var output strings.Builder
	if err := run(t.Context(), []string{"--version"}, strings.NewReader(""), &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if output.String() != "proxyctl 1.6.0-dev\n" {
		t.Fatalf("version output = %q", output.String())
	}
}

func TestTOTPRecoveryCommandsRejectNonRoot(t *testing.T) {
	if os.Getenv("PROXYCTL_PRIVILEGE_HELPER") == "1" {
		err := run(t.Context(), []string{"reset-totp"}, strings.NewReader(""), os.Stdout, os.Stderr)
		if err == nil || !strings.Contains(err.Error(), "must be run as root") {
			t.Fatalf("non-root TOTP command error = %v", err)
		}
		return
	}
	work := t.TempDir()
	if err := os.Chmod(filepath.Dir(work), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(work, 0o755); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(work, "proxyctl.test")
	copyFile, err := os.OpenFile(copyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		_ = binary.Close()
		t.Fatal(err)
	}
	if _, err := io.Copy(copyFile, binary); err != nil {
		_ = binary.Close()
		_ = copyFile.Close()
		t.Fatal(err)
	}
	if err := binary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := copyFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(copyPath, 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(copyPath, "-test.run=^TestTOTPRecoveryCommandsRejectNonRoot$")
	command.Env = append(os.Environ(), "PROXYCTL_PRIVILEGE_HELPER=1")
	if os.Geteuid() == 0 {
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("non-root privilege check failed: %v: %s", err, output)
	}
}
