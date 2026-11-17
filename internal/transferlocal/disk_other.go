//go:build !linux && !darwin && !windows

package transferlocal

// freeBytes is unknown on platforms without a vetted free-space call; the
// chunked download then skips its disk preflight.
func freeBytes(string) (int64, bool) { return 0, false }
