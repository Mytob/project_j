//go:build !linux

package admin

// Package uploads are only enabled in the Linux production deployment. The
// cross-platform test build still compiles the admin package without claiming
// a meaningful host free-space reading.
func availableBytes(string) (int64, error) { return -1, nil }
