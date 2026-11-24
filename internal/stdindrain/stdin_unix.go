//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package stdindrain

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func drainPlatform() error {
	fd := int(os.Stdin.Fd())
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return ErrDrain
	}
	return Drain(IdleWindow, MaxBytes, func(wait time.Duration) (bool, error) {
		ms := int(wait / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, ms)
		return n > 0 && fds[0].Revents&unix.POLLIN != 0, err
	}, func(p []byte) (int, error) { return unix.Read(fd, p) })
}
