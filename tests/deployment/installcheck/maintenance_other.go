//go:build !linux

package main

import "errors"

func verifyRestrictedMaintenanceClient() error {
	return errors.New("restricted maintenance package check requires Linux")
}

func runMaintenanceProbe() error {
	return errors.New("restricted maintenance package check requires Linux")
}
