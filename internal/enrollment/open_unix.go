//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly || solaris

package enrollment

import (
	"errors"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// openSafeFile uses Unix openat/no-follow flags supported by the platform syscall
// implementations. Each directory handle pins the traversed ancestry, so parent
// replacement cannot redirect subsequent opens. Mount points and hard links are
// not rejected; a pathname naming them can still designate a regular file.
func openSafeFile(name string) (*os.File, error) {
	if !path.IsAbs(name) || strings.IndexByte(name, 0) >= 0 {
		return nil, errors.New("path must be absolute")
	}
	clean := path.Clean(name)
	if clean != name {
		return nil, errors.New("path must be normalized and contain no traversal components")
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	leaf := parts[len(parts)-1]
	if leaf == "" || leaf == "." {
		unix.Close(fd)
		return nil, errors.New("path must name a regular file")
	}
	fileFD, err := unix.Openat(fd, leaf, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil {
		unix.Close(fileFD)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fileFD)
		return nil, errors.New("path must name a regular file")
	}
	return os.NewFile(uintptr(fileFD), name), nil
}
