//go:build linux

package appstoresink

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// beginTrace is nil outside tests. A test installs it to learn, on failure,
// which step of Begin refused and what the child looked like at that moment.
var beginTrace atomic.Pointer[func(string)]

// beginFailed returns result unchanged; the description is built only when a
// test listens and holds process metadata, never frame or secret bytes.
func beginFailed(site string, pid int, identity [2]uint64, cause, result error) error {
	trace := beginTrace.Load()
	if trace == nil {
		return result
	}
	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	exe, linkErr := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	var st unix.Stat_t
	statErr := unix.Stat(fmt.Sprintf("/proc/%d/exe", pid), &st)
	(*trace)(fmt.Sprintf("begin failed at %s: result=%v cause=%v pid=%d comm=%q exe=%q (%v) got=[%d %d] (%v) want=%v uid=%d euid=%d",
		site, result, cause, pid, strings.TrimSpace(string(comm)), exe, linkErr, uint64(st.Dev), st.Ino, statErr, identity, st.Uid, os.Geteuid()))
	return result
}
