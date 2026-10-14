//go:build linux

package monitoring

import (
	"errors"
	"syscall"
)

func diskUsage(path string) (used, free, total uint64, err error) {
	if path == "" {
		path = "/host/root"
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0, err
	}
	blockSize := uint64(stat.Bsize)
	blocks := uint64(stat.Blocks)
	available := uint64(stat.Bavail)
	if blockSize == 0 || blocks > ^uint64(0)/blockSize || available > blocks {
		return 0, 0, 0, errors.New("host filesystem counters are invalid")
	}
	total = blocks * blockSize
	free = available * blockSize
	used = total - free
	return used, free, total, nil
}
