//go:build !windows

package transferlocal

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// pathInfo is the no-follow inspection result for one path.
type pathInfo struct {
	exist       bool
	dir         bool
	regular     bool
	reparse     bool // symlink on unix
	multiLinked bool // regular file with link count > 1
	size        int64
	mode        os.FileMode
}

// statPath inspects path without following symlinks. A missing path returns
// pathInfo{exist:false} and a nil error.
func statPath(path string) (pathInfo, error) {
	info := pathInfo{}
	raw, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return pathInfo{}, nil
		}
		return pathInfo{}, err
	}
	mode := raw.Mode()
	info.exist = true
	info.dir = mode.IsDir()
	info.reparse = mode&os.ModeSymlink != 0
	info.regular = mode.IsRegular()
	info.size = raw.Size()
	info.mode = mode
	if info.regular {
		if st, ok := raw.Sys().(*syscall.Stat_t); ok && uint64(st.Nlink) > 1 {
			info.multiLinked = true
		}
	}
	return info, nil
}

// pathIdentity returns a stable per-file identity string "dev:ino" used to
// verify that a staging path still holds the object this job created.
func pathIdentity(path string) (string, error) {
	raw, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	st, ok := raw.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("path identity is unavailable")
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10) + ":" + strconv.FormatUint(uint64(st.Mode&syscall.S_IFMT), 8), nil
}

// openRegularNoFollow opens an existing regular file without following
// symlinks and verifies regularness on the open handle. O_NONBLOCK prevents
// hanging on a FIFO; the Fstat rejects non-regulars.
func openRegularNoFollow(path string) (*os.File, int64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	file := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		file.Close()
		return nil, 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		file.Close()
		return nil, 0, errors.New("path is not a regular file")
	}
	return file, st.Size, nil
}

// createExclusiveFile creates a new regular file exclusively and without
// following links.
func createExclusiveFile(path string, mode os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, errDestinationExists
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// createPrivateDir creates a directory exclusively with owner-only
// permissions.
func createPrivateDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errDestinationExists
		}
		return err
	}
	return nil
}

// createStageDir creates the keyed chunk staging directory exclusively with
// owner-only permissions.
func createStageDir(path string) error {
	return createPrivateDir(path)
}

// privateOwnedDir reports whether the directory is private (mode 0700 with no
// special bits) and owned by the current user. info is the no-follow
// inspection of path.
func privateOwnedDir(path string, info pathInfo) bool {
	if info.mode.Perm() != 0o700 || info.mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	raw, err := os.Lstat(path)
	if err != nil {
		return false
	}
	st, ok := raw.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// setPublishedRootMode gives a staged directory the mode its subdirectories
// are created with, before it is published by rename.
func setPublishedRootMode(path string) error {
	return os.Chmod(path, 0755)
}

// syncDirectory flushes a directory entry list.
func syncDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

// syncPathData flushes the data of an existing regular file opened without
// following links.
func syncPathData(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	raw, err := file.Stat()
	if err != nil {
		return err
	}
	if !raw.Mode().IsRegular() {
		return errors.New("path is not a regular file")
	}
	return file.Sync()
}

// hardLinkNoClobber creates target as a hard link to existing.
func hardLinkNoClobber(existing, target string) error {
	err := unix.Linkat(unix.AT_FDCWD, existing, unix.AT_FDCWD, target, 0)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, unix.EEXIST):
		return errDestinationExists
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EXDEV):
		return errHardLinkUnsupported
	}
	return err
}

// renameReplaceFile atomically replaces an existing regular file at target
// with source.
func renameReplaceFile(source, target string) error {
	return os.Rename(source, target)
}
