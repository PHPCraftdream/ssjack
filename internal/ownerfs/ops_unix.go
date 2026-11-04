//go:build linux || darwin

package ownerfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/PHPCraftdream/ssjack/internal/ownerrename"
)

func lock(root *os.File, name string) (func() error, error) {
	file, err := openFile(root, name, true, false)
	if errors.Is(err, ErrMissing) {
		file, err = openFile(root, name, true, true)
	}
	if errors.Is(err, ErrExists) {
		file, err = openFile(root, name, true, false)
	}
	if err != nil {
		return nil, err
	}
	info, err := stat(file, false)
	if err != nil || info.Size != 0 || info.Directory {
		file.Close()
		return nil, ErrInvalid
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, mapError(err)
	}
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			result = mapError(unix.Flock(int(file.Fd()), unix.LOCK_UN))
			if err := file.Close(); result == nil && err != nil {
				result = ErrUnavailable
			}
		})
		return result
	}, nil
}

func temporary(root *os.File) (*os.File, error) {
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, ErrUnavailable
	}
	name := ".spool-" + hex.EncodeToString(identity[:]) + ".tmp"
	file, err := openFile(root, name, true, true)
	if err != nil {
		return nil, err
	}
	// Unlink the empty inode before any caller can write ciphertext to it.
	if unix.Unlinkat(int(root.Fd()), name, 0) != nil {
		file.Close()
		return nil, ErrUncertain
	}
	if unix.Fsync(int(root.Fd())) != nil {
		file.Close()
		return nil, ErrUncertain
	}
	metadata, err := stat(file, true)
	if err != nil || metadata.Size != 0 || metadata.Directory {
		file.Close()
		return nil, ErrInvalid
	}
	if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}

func rename(source *os.File, name string, destination *os.File, target string, replace bool) error {
	file, err := openFile(source, name, true, false)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := stat(file, false)
	if err != nil || before.Directory {
		return ErrInvalid
	}
	if err := ownerrename.Rename(source.Fd(), name, destination.Fd(), target, replace); err != nil {
		return mapError(err)
	}
	if unix.Fsync(int(source.Fd())) != nil || unix.Fsync(int(destination.Fd())) != nil {
		return ErrUncertain
	}
	published, err := openFile(destination, target, false, false)
	if err != nil {
		return ErrUncertain
	}
	defer published.Close()
	after, err := stat(published, false)
	if err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.MtimeSec != before.MtimeSec || after.MtimeNsec != before.MtimeNsec {
		return ErrUncertain
	}
	return nil
}

func entries(root *os.File, visit func(string) error) error {
	fd, err := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "owner-directory-entries")
	defer file.Close()
	before, err := stat(root, false)
	if err != nil {
		return err
	}
	actual, err := stat(file, false)
	if err != nil || before.Dev != actual.Dev || before.Ino != actual.Ino {
		return ErrChanged
	}
	count := 0
	for {
		batch, err := file.ReadDir(256)
		for _, entry := range batch {
			count++
			if count > 1<<20 || !atom(entry.Name()) {
				return ErrInvalid
			}
			if err := visit(entry.Name()); err != nil {
				return err
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return ErrUnavailable
		}
	}
}
