//go:build linux

package appstorefile

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func canonicalName(kind, name string) bool {
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return false
	}
	switch kind {
	case "snapshots", "candidates", "intents", "quarantine":
		if len(name) != 36 || name[32:] != ".bin" {
			return false
		}
		b, e := hex.DecodeString(name[:32])
		return e == nil && len(b) == 16 && hex.EncodeToString(b) == name[:32] && string(b) != string(make([]byte, 16))
	case "recovery":
		if len(name) != 69 || name[32] != '-' || name[65:] != ".bin" {
			return false
		}
		a, e := hex.DecodeString(name[:32])
		if e != nil || hex.EncodeToString(a) != name[:32] || string(a) == string(make([]byte, 16)) {
			return false
		}
		b, e := hex.DecodeString(name[33:65])
		return e == nil && hex.EncodeToString(b) == name[33:65] && string(b) != string(make([]byte, 16))
	}
	return false
}

func errno(e error) error {
	if e == unix.ENOENT {
		return ErrMissing
	}
	if e == unix.EEXIST {
		return ErrExists
	}
	return ErrUnavailable
}

func pointer(t *Transaction, tuple [64]byte) error {
	s, e := live(t)
	if e != nil {
		return e
	}
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		return ErrUnavailable
	}
	name := hex.EncodeToString(random[:]) + ".ptr"
	f, e := createAt(s.fd, name)
	if e != nil {
		return e
	}
	if e = writeExact(f, tuple[:]); e != nil {
		_ = f.Close()
		return ErrUncertain
	}
	if e = f.Sync(); e != nil {
		_ = f.Close()
		return ErrUncertain
	}
	before, e := statFile(f)
	if e != nil {
		_ = f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return ErrUncertain
	}
	fd, x := unix.Openat(s.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if x != nil {
		return ErrUncertain
	}
	check := os.NewFile(uintptr(fd), name)
	var got [64]byte
	n, x := io.ReadFull(check, got[:])
	after, y := statFile(check)
	ce := check.Close()
	if x != nil || n != 64 || y != nil || after != before || got != tuple || ce != nil {
		return ErrUncertain
	}
	if x = unix.Renameat(s.fd, name, s.fd, "pointer.bin"); x != nil {
		return ErrUncertain
	}
	if unix.Fsync(s.fd) != nil {
		return ErrUncertain
	}
	return nil
}

func quarantine(t *Transaction, id [16]byte) error {
	if id == ([16]byte{}) {
		return ErrInvalid
	}
	s, err := live(t)
	if err != nil {
		return err
	}
	src, dst := s.dirs["candidates"], s.dirs["quarantine"]
	name := hexID(id) + ".bin"
	if !canonicalName("quarantine", name) {
		return ErrInvalid
	}
	if err = validDir(src); err != nil {
		return err
	}
	if err = validDir(dst); err != nil {
		return err
	}
	err = unix.Renameat2(src, name, dst, name, unix.RENAME_NOREPLACE)
	if err != nil {
		if err == unix.ENOSYS || err == unix.EINVAL || err == unix.EOPNOTSUPP {
			return ErrUnsupported
		}
		if err != unix.ENOENT {
			return errno(err)
		}
		f, targetErr := openNamed(t, "quarantine", name)
		if targetErr != nil {
			if targetErr == ErrMissing {
				return ErrMissing
			}
			return targetErr
		}
		_, statErr := statFile(f)
		closeErr := f.Close()
		if statErr != nil {
			return statErr
		}
		if closeErr != nil {
			return ErrUnavailable
		}
		if unix.Fsync(src) != nil || unix.Fsync(dst) != nil {
			return ErrUncertain
		}
		return nil
	}
	if unix.Fsync(src) != nil || unix.Fsync(dst) != nil {
		return ErrUncertain
	}
	f, err := openNamed(t, "quarantine", name)
	if err != nil {
		return err
	}
	_, statErr := statFile(f)
	closeErr := f.Close()
	if statErr != nil {
		return statErr
	}
	if closeErr != nil {
		return ErrUnavailable
	}
	return nil
}

func syncJournal(t *Transaction) error {
	s, err := live(t)
	if err != nil {
		return err
	}
	f, err := journal(t)
	if err != nil {
		return err
	}
	before, err := statFile(f)
	if err != nil {
		_ = f.Close()
		return err
	}
	if f.Sync() != nil {
		_ = f.Close()
		return ErrUncertain
	}
	if unix.Fsync(s.fd) != nil {
		_ = f.Close()
		return ErrUncertain
	}
	after, statErr := statFile(f)
	closeErr := f.Close()
	if statErr != nil {
		return statErr
	}
	if before != after {
		return ErrChanged
	}
	if closeErr != nil {
		return ErrUnavailable
	}
	return nil
}
func readPointer(t *Transaction) ([64]byte, error) {
	var tuple [64]byte
	s, e := live(t)
	if e != nil {
		return tuple, e
	}
	fd, x := unix.Openat(s.fd, "pointer.bin", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if x != nil {
		return tuple, errno(x)
	}
	f := os.NewFile(uintptr(fd), "appstore-pointer")
	st, x := fileFD(f)
	if x != nil {
		_ = f.Close()
		return tuple, x
	}
	if st.Size != 64 {
		_ = f.Close()
		return tuple, ErrInvalid
	}
	rev0 := rev(st)
	n, x := io.ReadFull(f, tuple[:])
	rev1, y := statFile(f)
	ce := f.Close()
	if x != nil || n != 64 || y != nil || rev0 != rev1 {
		return [64]byte{}, ErrChanged
	}
	if ce != nil {
		return [64]byte{}, ErrUnavailable
	}
	return tuple, nil
}
