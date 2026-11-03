//go:build linux

package appstoreintentio

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
)

func validDirectory(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == 0700 && st.Uid == uint32(os.Geteuid()) && st.Nlink > 0
}

func validFile(st *unix.Stat_t, size int64) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && st.Size == size
}

func newDirectory(directory *os.File, store [16]byte) (*Directory, error) {
	if directory == nil || store == ([16]byte{}) {
		return nil, ErrInvalid
	}
	defer runtime.KeepAlive(directory)
	var before unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &before); err != nil || !validDirectory(&before) {
		return nil, ErrInvalid
	}
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !validDirectory(&after) || before.Dev != after.Dev || before.Ino != after.Ino {
		unix.Close(fd)
		return nil, ErrInvalid
	}
	return &Directory{state: &directoryState{fd: fd, store: store, syncFile: unix.Fsync}}, nil
}

func lockDirectory(s *directoryState) error {
	var st unix.Stat_t
	if err := unix.Fstat(s.fd, &st); err != nil {
		return ErrUnavailable
	}
	if !validDirectory(&st) {
		return ErrInvalid
	}
	if err := unix.Flock(s.fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return ErrBusy
		}
		return ErrUnavailable
	}
	return nil
}

func unlockDirectory(s *directoryState) { _ = unix.Flock(s.fd, unix.LOCK_UN) }
func closeDirectory(s *directoryState) error {
	if err := unix.Close(s.fd); err != nil {
		return ErrUnavailable
	}
	return nil
}

func name(transaction [16]byte) string {
	return "intent-" + hex.EncodeToString(transaction[:]) + ".bin"
}

func create(s *directoryState, raw [appstoreanchorrequest.IntentSize]byte) error {
	defer clear(raw[:])
	transaction := [16]byte(raw[8:24])
	fd, err := unix.Openat(s.fd, name(transaction), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return ErrExists
		}
		return ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "application-store-intent")
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return ErrUnavailable
	}
	if !validFile(&st, 0) {
		return ErrInvalid
	}
	if n, err := file.Write(raw[:]); err != nil || n != len(raw) {
		return ErrUnavailable
	}
	if err := s.syncFile(fd); err != nil {
		return ErrUnavailable
	}
	if err := file.Close(); err != nil {
		return ErrUnavailable
	}
	if err := s.syncFile(s.fd); err != nil {
		return ErrUnavailable
	}
	persisted, err := readRaw(s, transaction)
	defer clear(persisted[:])
	if err != nil {
		return err
	}
	if !bytes.Equal(raw[:], persisted[:]) {
		return ErrInvalid
	}
	return nil
}

func readRaw(s *directoryState, transaction [16]byte) ([appstoreanchorrequest.IntentSize]byte, error) {
	var raw [appstoreanchorrequest.IntentSize]byte
	fd, err := unix.Openat(s.fd, name(transaction), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return raw, ErrNotFound
		}
		if errors.Is(err, unix.ELOOP) {
			return raw, ErrInvalid
		}
		return raw, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "application-store-intent")
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return raw, ErrUnavailable
	}
	if !validFile(&before, appstoreanchorrequest.IntentSize) {
		return raw, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(file, appstoreanchorrequest.IntentSize+1))
	defer clear(b)
	if err != nil {
		return raw, ErrUnavailable
	}
	if len(b) != len(raw) {
		return raw, ErrInvalid
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return raw, ErrUnavailable
	}
	if !validFile(&after, appstoreanchorrequest.IntentSize) || before.Dev != after.Dev || before.Ino != after.Ino || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return raw, ErrInvalid
	}
	copy(raw[:], b)
	return raw, nil
}
