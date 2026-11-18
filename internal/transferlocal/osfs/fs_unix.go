//go:build !windows

package osfs

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// PathInfo is the no-follow inspection result for one path.
type PathInfo struct {
	Exist       bool
	Dir         bool
	Regular     bool
	Reparse     bool // symlink on unix
	MultiLinked bool // regular file with link count > 1
	Size        int64
	Mode        os.FileMode
}

// StatPath inspects path without following symlinks. A missing path returns
// PathInfo{exist:false} and a nil error.
func StatPath(path string) (PathInfo, error) {
	info := PathInfo{}
	raw, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return PathInfo{}, nil
		}
		return PathInfo{}, err
	}
	mode := raw.Mode()
	info.Exist = true
	info.Dir = mode.IsDir()
	info.Reparse = mode&os.ModeSymlink != 0
	info.Regular = mode.IsRegular()
	info.Size = raw.Size()
	info.Mode = mode
	if info.Regular {
		if st, ok := raw.Sys().(*syscall.Stat_t); ok && uint64(st.Nlink) > 1 {
			info.MultiLinked = true
		}
	}
	return info, nil
}

// PathIdentity returns a stable per-file identity string "dev:ino" used to
// verify that a staging path still holds the object this job created.
func PathIdentity(path string) (string, error) {
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

// OpenRegularNoFollow opens an existing regular file without following
// symlinks and verifies regularness on the open handle. O_NONBLOCK prevents
// hanging on a FIFO; the Fstat rejects non-regulars.
func OpenRegularNoFollow(path string) (*os.File, int64, error) {
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

// CreateExclusiveFile creates a new regular file exclusively and without
// following links.
func CreateExclusiveFile(path string, mode os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, ErrDestinationExists
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// CreatePrivateDir creates a directory exclusively with owner-only
// permissions.
func CreatePrivateDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrDestinationExists
		}
		return err
	}
	return nil
}

// CreateStageDir creates the keyed chunk staging directory exclusively with
// owner-only permissions.
func CreateStageDir(path string) error {
	return CreatePrivateDir(path)
}

// PrivateOwnedDir reports whether the directory is private (mode 0700 with no
// special bits) and owned by the current user. info is the no-follow
// inspection of path.
func PrivateOwnedDir(path string, info PathInfo) bool {
	if info.Mode.Perm() != 0o700 || info.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	raw, err := os.Lstat(path)
	if err != nil {
		return false
	}
	st, ok := raw.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// SetPublishedRootMode gives a staged directory the mode its subdirectories
// are created with, before it is published by rename.
func SetPublishedRootMode(path string) error {
	return os.Chmod(path, 0755)
}

// SyncDirectory flushes a directory entry list.
func SyncDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

// SyncPathData flushes the data of an existing regular file opened without
// following links.
func SyncPathData(path string) error {
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

// HardLinkNoClobber creates target as a hard link to existing.
func HardLinkNoClobber(existing, target string) error {
	err := unix.Linkat(unix.AT_FDCWD, existing, unix.AT_FDCWD, target, 0)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, unix.EEXIST):
		return ErrDestinationExists
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EXDEV):
		return ErrHardLinkUnsupported
	}
	return err
}

// RenameReplaceFile atomically replaces an existing regular file at target
// with source.
func RenameReplaceFile(source, target string) error {
	return os.Rename(source, target)
}
