//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/Mytob/project_j/internal/containerhealth"
)

func verifyRestrictedMaintenanceClient() error {
	socket := "/run/jellyfin-proxy-maintenance/maintenance.sock"
	if _, err := containerhealth.NewUnixClient(socket).Snapshot(context.Background()); err == nil {
		return errors.New("restricted maintenance service accepted an unauthorized root caller")
	}
	command := exec.Command(os.Args[0], "--probe-maintenance")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("admin UID could not read the restricted maintenance API: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runMaintenanceProbe() error {
	items, err := containerhealth.NewUnixClient("/run/jellyfin-proxy-maintenance/maintenance.sock").Snapshot(context.Background())
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("maintenance API returned no labeled application containers after install")
	}
	for _, item := range items {
		if item.Service == "" || item.State == "" {
			return errors.New("maintenance API returned an incomplete container health record")
		}
	}
	return nil
}
