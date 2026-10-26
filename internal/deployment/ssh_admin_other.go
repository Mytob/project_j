//go:build !linux

package deployment

import (
	"context"
	"errors"
)

type SSHAdministratorChange struct{}

func ConfigureSSHAdministrator(context.Context, SSHAdministratorConfig, CommandRunner) (*SSHAdministratorChange, error) {
	return nil, errors.New("SSH administrator configuration is supported only on Ubuntu Linux")
}

func DisableRootSSHLogin(context.Context, *SSHAdministratorChange, SSHAdministratorConfig, CommandRunner) error {
	return errors.New("SSH root-login configuration is supported only on Ubuntu Linux")
}

func RollbackSSHAdministrator(context.Context, *SSHAdministratorChange, CommandRunner) error {
	return errors.New("SSH administrator rollback is supported only on Ubuntu Linux")
}
