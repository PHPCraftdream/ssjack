//go:build linux || darwin

package transferlocal

import (
	"math"

	"golang.org/x/sys/unix"
)

// freeBytes returns the bytes available to unprivileged processes on the
// filesystem holding dir.
func freeBytes(dir string) (int64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, false
	}
	blocks, size := uint64(st.Bavail), uint64(st.Bsize)
	if size == 0 {
		return 0, false
	}
	if blocks > math.MaxInt64/size {
		return math.MaxInt64, true
	}
	return int64(blocks * size), true
}
