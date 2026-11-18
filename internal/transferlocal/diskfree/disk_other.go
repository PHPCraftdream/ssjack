//go:build !linux && !darwin && !windows

package diskfree

// FreeBytes is unknown on platforms without a vetted free-space call; the
// chunked download then skips its disk preflight.
func FreeBytes(string) (int64, bool) { return 0, false }
