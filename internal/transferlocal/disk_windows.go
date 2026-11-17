//go:build windows

package transferlocal

import (
	"math"

	"golang.org/x/sys/windows"
)

// freeBytes returns the bytes available to the calling user on the volume
// holding dir.
func freeBytes(dir string) (int64, bool) {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false
	}
	var available, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(name, &available, &total, &free); err != nil {
		return 0, false
	}
	if available > math.MaxInt64 {
		return math.MaxInt64, true
	}
	return int64(available), true
}
