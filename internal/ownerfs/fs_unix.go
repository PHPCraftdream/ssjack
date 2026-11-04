//go:build linux || darwin

package ownerfs

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

func mapError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, unix.ENOENT):
		return ErrMissing
	case errors.Is(err, unix.EEXIST):
		return ErrExists
	case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN):
		return ErrBusy
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP):
		return ErrUnsupported
	}
	return ErrUnavailable
}
func stat(file *os.File, anonymous bool) (Metadata, error) {
	if file == nil {
		return Metadata{}, ErrInvalid
	}
	var value unix.Stat_t
	if unix.Fstat(int(file.Fd()), &value) != nil || value.Uid != uint32(os.Geteuid()) || value.Size < 0 {
		return Metadata{}, ErrInvalid
	}
	directory := value.Mode&unix.S_IFMT == unix.S_IFDIR
	permission, links := uint32(0600), uint64(1)
	if directory {
		permission = 0700
	}
	if anonymous {
		links = 0
	}
	if uint32(value.Mode)&07777 != permission || (directory && (anonymous || value.Nlink == 0)) || (!directory && (value.Mode&unix.S_IFMT != unix.S_IFREG || uint64(value.Nlink) != links)) {
		return Metadata{}, ErrInvalid
	}
	mtime, mnano, ok := unixTime(value, "Mtim", "Mtimespec")
	ctime, cnano, changed := unixTime(value, "Ctim", "Ctimespec")
	if !ok || !changed {
		return Metadata{}, ErrUnsupported
	}
	return Metadata{Dev: uint64(value.Dev), Ino: value.Ino, Links: uint64(value.Nlink), Size: value.Size, MtimeSec: mtime, MtimeNsec: mnano, CtimeSec: ctime, CtimeNsec: cnano, Directory: directory}, nil
}

func unixTime(value unix.Stat_t, primary, alternate string) (int64, int64, bool) {
	stamp := reflect.ValueOf(value).FieldByName(primary)
	if !stamp.IsValid() {
		stamp = reflect.ValueOf(value).FieldByName(alternate)
	}
	if !stamp.IsValid() || stamp.Kind() != reflect.Struct {
		return 0, 0, false
	}
	seconds, nanos := stamp.FieldByName("Sec"), stamp.FieldByName("Nsec")
	if !seconds.IsValid() || !nanos.IsValid() || !seconds.CanInt() || !nanos.CanInt() || nanos.Int() < 0 || nanos.Int() >= 1e9 {
		return 0, 0, false
	}
	return seconds.Int(), nanos.Int(), true
}

func walk(path string, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrInvalid
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	if filepath.Clean(path) == "/" {
		if private {
			unix.Close(fd)
			return nil, ErrInvalid
		}
		return os.NewFile(uintptr(fd), "/"), nil
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return nil, ErrInvalid
		}
		var named, parent unix.Stat_t
		if unix.Fstat(fd, &parent) != nil || unix.Fstatat(fd, part, &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
			unix.Close(fd)
			return nil, ErrUnavailable
		}
		flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		// macOS system aliases are allowed only beneath a protected root-owned parent.
		if runtime.GOOS == "darwin" && i == 0 && (part == "var" || part == "tmp" || part == "etc") && named.Mode&unix.S_IFMT == unix.S_IFLNK && named.Uid == 0 && parent.Uid == 0 && parent.Mode&0022 == 0 && (!private || i != len(parts)-1) {
			flags &^= unix.O_NOFOLLOW
		}
		next, err := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, mapError(err)
		}
		fd = next
		var value unix.Stat_t
		if unix.Fstat(fd, &value) != nil || value.Mode&unix.S_IFMT != unix.S_IFDIR || value.Nlink == 0 {
			unix.Close(fd)
			return nil, ErrInvalid
		}
		valid := (value.Uid == 0 || value.Uid == uint32(os.Geteuid())) && (value.Mode&0022 == 0 || value.Mode&unix.S_ISVTX != 0)
		if private && i == len(parts)-1 {
			valid = value.Uid == uint32(os.Geteuid()) && value.Mode&07777 == 0700
		}
		if !valid {
			unix.Close(fd)
			return nil, ErrInvalid
		}
	}
	return os.NewFile(uintptr(fd), filepath.Clean(path)), nil
}
func openRoot(path string) (*Root, error) {
	file, err := walk(path, true)
	if err != nil {
		return nil, err
	}
	return &Root{file: file}, nil
}
func duplicate(file *os.File) (*os.File, error) {
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}
func adoptRoot(file *os.File) (*Root, error) {
	before, err := stat(file, false)
	if err != nil || !before.Directory {
		return nil, ErrInvalid
	}
	owned, err := duplicate(file)
	if err != nil {
		return nil, err
	}
	after, err := stat(owned, false)
	if err != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		owned.Close()
		return nil, ErrChanged
	}
	return &Root{file: owned}, nil
}
func makeRoot(path string) (*Root, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	parent, err := walk(filepath.Dir(filepath.Clean(path)), false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name := filepath.Base(path)
	if name == "." || name == ".." || name == "/" {
		return nil, ErrInvalid
	}
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return nil, mapError(err)
	}
	if err := unix.Fsync(int(parent.Fd())); err != nil {
		return nil, ErrUncertain
	}
	return child(parent, name, false)
}
func child(root *os.File, name string, create bool) (*Root, error) {
	if create {
		if err := unix.Mkdirat(int(root.Fd()), name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, mapError(err)
		}
		if unix.Fsync(int(root.Fd())) != nil {
			return nil, ErrUncertain
		}
	}
	fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, mapError(err)
	}
	file := os.NewFile(uintptr(fd), name)
	if info, err := stat(file, false); err != nil || !info.Directory {
		file.Close()
		return nil, ErrInvalid
	}
	return &Root{file: file}, nil
}
func openFile(root *os.File, name string, write, exclusive bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if write {
		flags = (flags &^ unix.O_RDONLY) | unix.O_RDWR
	}
	if exclusive {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(int(root.Fd()), name, flags, 0600)
	if err != nil {
		return nil, mapError(err)
	}
	file := os.NewFile(uintptr(fd), name)
	if info, err := stat(file, false); err != nil || info.Directory {
		file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}
func remove(root *os.File, name string) error {
	file, err := openFile(root, name, false, false)
	if err != nil {
		return err
	}
	defer file.Close()
	if unix.Unlinkat(int(root.Fd()), name, 0) != nil {
		return ErrUncertain
	}
	if unix.Fsync(int(root.Fd())) != nil {
		return ErrUncertain
	}
	return nil
}
func flush(root *os.File, name string) error {
	file, err := openFile(root, name, true, false)
	if err != nil {
		return err
	}
	defer file.Close()
	if file.Sync() != nil || unix.Fsync(int(root.Fd())) != nil {
		return ErrUncertain
	}
	return nil
}
