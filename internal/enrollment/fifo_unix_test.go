//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly || solaris

package enrollment

import "golang.org/x/sys/unix"

func makeFIFO(path string) error { return unix.Mkfifo(path, 0600) }
