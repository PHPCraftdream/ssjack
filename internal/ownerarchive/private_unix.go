//go:build !windows

package ownerarchive

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openArchive opens an existing regular file for reading exactly once. O_NONBLOCK
// keeps open(2) of a FIFO or device from blocking, O_NOFOLLOW refuses a symlink
// final component, and the type is checked on the open descriptor, so a path
// swapped after any earlier check cannot be read or wedge the caller.
func openArchive(path string) (*os.File, error) {
	var fd int
	var err error
	for {
		fd, err = unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return nil, ErrArchive
	}
	var st unix.Stat_t
	for {
		err = unix.Fstat(fd, &st)
		if err != unix.EINTR {
			break
		}
	}
	// Blocking mode is restored only after the type check so Go's reads of a
	// regular file behave normally.
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || unix.SetNonblock(fd, false) != nil {
		unix.Close(fd)
		return nil, ErrArchive
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, ErrArchive
	}
	return file, nil
}

func newPrivateFile(destination string) (*os.File, error) {
	return os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

func checkPrivateFile(_ *os.File, identity os.FileInfo) error {
	if !identity.Mode().IsRegular() || identity.Mode().Perm() != 0600 {
		return errors.New("owner export file permissions are not private")
	}
	return nil
}
