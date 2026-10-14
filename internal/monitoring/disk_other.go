//go:build !linux

package monitoring

import "errors"

func diskUsage(string) (uint64, uint64, uint64, error) {
	return 0, 0, 0, errors.New("host filesystem measurements require Linux")
}
