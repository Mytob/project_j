//go:build !linux

package deployment

import "errors"

func InspectInstallResources(string, string) (InstallResourceReport, error) {
	return InstallResourceReport{}, errors.New("installation resource preflight is available only on Ubuntu Linux")
}
