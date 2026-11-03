//go:build linux

package appstoreentry

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxBinding = 300 << 10
const bindingName = "binding.bin"

var ErrUnsupported = errors.New("protected installation storage requires Linux")
var errStorage = errors.New("protected storage operation failed")

func Supported() bool { return true }

type Store struct {
	dir, lock   *os.File
	path        string
	dev, ino    uint64
	bindingStat unix.Stat_t
	loaded      bool
}

func openDirectory(path string) (int, unix.Stat_t, error) {
	if !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return -1, unix.Stat_t{}, errStorage
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, errStorage
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return -1, unix.Stat_t{}, errStorage
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			unix.Close(fd)
			return -1, unix.Stat_t{}, errStorage
		}
		var st unix.Stat_t
		e = unix.Fstat(next, &st)
		valid := e == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Nlink > 0
		if i == len(parts)-1 {
			valid = valid && st.Mode&07777 == 0700 && st.Uid == uint32(os.Geteuid())
		} else {
			valid = valid && (st.Uid == 0 || st.Uid == uint32(os.Geteuid())) && (st.Mode&0022 == 0 || part == "tmp" && st.Mode&unix.S_ISVTX != 0)
		}
		if !valid {
			unix.Close(next)
			unix.Close(fd)
			return -1, unix.Stat_t{}, errStorage
		}
		unix.Close(fd)
		fd = next
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		unix.Close(fd)
		return -1, unix.Stat_t{}, errStorage
	}
	return fd, st, nil
}

func Open(path string) (*Store, error) {
	fd, st, err := openDirectory(path)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), filepath.Clean(path))
	l, err := unix.Openat(fd, ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		dir.Close()
		return nil, errStorage
	}
	var ls unix.Stat_t
	if unix.Fstat(l, &ls) != nil || ls.Mode&unix.S_IFMT != unix.S_IFREG || ls.Mode&07777 != 0600 || ls.Uid != uint32(os.Geteuid()) || ls.Nlink != 1 || unix.Flock(l, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unix.Close(l)
		dir.Close()
		return nil, errStorage
	}
	return &Store{dir: dir, lock: os.NewFile(uintptr(l), ".lock"), path: filepath.Clean(path), dev: uint64(st.Dev), ino: st.Ino}, nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.lock != nil {
		err = s.lock.Close()
		s.lock = nil
	}
	if s.dir != nil {
		if e := s.dir.Close(); err == nil {
			err = e
		}
		s.dir = nil
	}
	return err
}

func (s *Store) Identity() (dev, ino uint64, err error) {
	if err := s.checkDir(); err != nil {
		return 0, 0, errStorage
	}
	return s.dev, s.ino, nil
}

func (s *Store) Root() (*os.File, error) {
	if s.checkDir() != nil {
		return nil, errStorage
	}
	fd, err := unix.FcntlInt(uintptr(s.dir.Fd()), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, errStorage
	}
	return os.NewFile(uintptr(fd), "installation-root"), nil
}

func (s *Store) checkDir() error {
	if s == nil || s.dir == nil {
		return errStorage
	}
	var st unix.Stat_t
	if unix.Fstat(int(s.dir.Fd()), &st) != nil || uint64(st.Dev) != s.dev || st.Ino != s.ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		return errStorage
	}
	fd, again, err := openDirectory(s.path)
	if err != nil {
		return errStorage
	}
	unix.Close(fd)
	if uint64(again.Dev) != s.dev || again.Ino != s.ino {
		return errStorage
	}
	return nil
}

func sameRevision(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Rdev == b.Rdev && a.Size == b.Size && a.Blksize == b.Blksize && a.Blocks == b.Blocks && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (s *Store) readBinding() ([]byte, unix.Stat_t, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), bindingName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, unix.Stat_t{}, errStorage
	}
	f := os.NewFile(uintptr(fd), bindingName)
	defer f.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size <= 0 || before.Size > maxBinding {
		return nil, unix.Stat_t{}, errStorage
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBinding+1))
	var after, named unix.Stat_t
	if err != nil || len(b) != int(before.Size) || unix.Fstat(fd, &after) != nil || !sameRevision(before, after) || unix.Fstatat(int(s.dir.Fd()), bindingName, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || named.Dev != after.Dev || named.Ino != after.Ino {
		return nil, unix.Stat_t{}, errStorage
	}
	return b, after, nil
}

func (s *Store) RequireUninstalled() error {
	if s.checkDir() != nil {
		return errStorage
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(s.dir.Fd()), bindingName, &st, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return errStorage
	}
	return nil
}

func (s *Store) Install(b []byte) error {
	if len(b) == 0 || len(b) > maxBinding || s.checkDir() != nil {
		return errStorage
	}
	fd, err := unix.Openat(int(s.dir.Fd()), bindingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errStorage
	}
	f := os.NewFile(uintptr(fd), bindingName)
	n, writeErr := f.Write(b)
	syncErr := f.Sync()
	var installed unix.Stat_t
	statErr := unix.Fstat(fd, &installed)
	closeErr := f.Close()
	if writeErr != nil || n != len(b) || syncErr != nil || statErr != nil || closeErr != nil || installed.Mode&unix.S_IFMT != unix.S_IFREG || installed.Mode&07777 != 0600 || installed.Uid != uint32(os.Geteuid()) || installed.Nlink != 1 {
		return errStorage
	}
	if s.dir.Sync() != nil {
		return errStorage
	}
	got, loaded, err := s.readBinding()
	if err != nil || !bytes.Equal(got, b) || loaded.Dev != installed.Dev || loaded.Ino != installed.Ino {
		return errStorage
	}
	s.bindingStat, s.loaded = loaded, true
	return nil
}

func (s *Store) Load() ([]byte, [32]byte, error) {
	var zero [32]byte
	if s.checkDir() != nil {
		return nil, zero, errStorage
	}
	b, st, err := s.readBinding()
	if err != nil {
		return nil, zero, errStorage
	}
	s.bindingStat, s.loaded = st, true
	return b, sha256.Sum256(b), nil
}

func (s *Store) VerifyUnchanged(h [32]byte) error {
	if s.checkDir() != nil || !s.loaded {
		return errStorage
	}
	b, st, err := s.readBinding()
	if err != nil || !sameRevision(s.bindingStat, st) || sha256.Sum256(b) != h {
		return errStorage
	}
	return nil
}
