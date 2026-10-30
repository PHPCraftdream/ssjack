//go:build linux

package appstorefile

import (
	"context"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func retain(t *Transaction, ctx context.Context, snapshot, txn [16]byte, source *os.File, expected [32]byte, limit uint64) error {
	if snapshot == ([16]byte{}) || txn == ([16]byte{}) || expected == ([32]byte{}) || limit > 1<<42 {
		return ErrInvalid
	}
	h, e := hashFile(ctx, source, limit)
	if e != nil {
		return e
	}
	if h != expected {
		return ErrChanged
	}
	before, e := statFile(source)
	if e != nil {
		return e
	}
	if uint64(before.Size) > limit {
		return ErrInvalid
	}
	s, e := live(t)
	if e != nil {
		return e
	}
	dir, ok := s.dirs["recovery"]
	if !ok {
		return ErrInvalid
	}
	if e = validDir(dir); e != nil {
		return e
	}
	name := hexID(snapshot) + "-" + hexID(txn) + ".bin"
	fd, x := unix.Openat(dir, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if x != nil {
		return errno(x)
	}
	f := os.NewFile(uintptr(fd), "appstore-recovery")
	good := false
	defer func() {
		if !good {
			_ = f.Close()
		}
	}()
	buf := make([]byte, 65536)
	left := before.Size
	for left > 0 {
		if e = ctx.Err(); e != nil {
			return e
		}
		n := int64(len(buf))
		if n > left {
			n = left
		}
		if _, e = io.ReadFull(source, buf[:n]); e != nil {
			return ErrChanged
		}
		off := 0
		for off < int(n) {
			written, x := f.Write(buf[off:int(n)])
			if x != nil || written == 0 {
				return ErrUncertain
			}
			off += written
		}
		left -= n
	}
	after, e := statFile(source)
	if e != nil || after != before {
		return ErrChanged
	}
	if f.Sync() != nil {
		return ErrUncertain
	}
	if f.Close() != nil {
		return ErrUncertain
	}
	if unix.Fsync(dir) != nil {
		return ErrUncertain
	}
	good = true
	copyFile, e := openNamed(t, "recovery", name)
	if e != nil {
		return e
	}
	got, x := hashFile(ctx, copyFile, limit)
	ce := copyFile.Close()
	if x != nil {
		return x
	}
	if ce != nil {
		return ErrUnavailable
	}
	if got != expected {
		return ErrChanged
	}
	return nil
}
func writeExact(f *os.File, b []byte) error {
	for len(b) > 0 {
		n, e := f.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func createAt(dir int, name string) (*os.File, error) {
	fd, e := unix.Openat(dir, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, errno(e)
	}
	f := os.NewFile(uintptr(fd), name)
	if _, e = fileFD(f); e != nil {
		_ = f.Close()
		return nil, e
	}
	return f, nil
}
func createIntent(t *Transaction, txn [16]byte, raw [312]byte) error {
	if txn == ([16]byte{}) || string(raw[:8]) != "SSAPCMT1" || string(raw[8:24]) != string(txn[:]) {
		return ErrInvalid
	}
	s, e := live(t)
	if e != nil {
		return e
	}
	dir, ok := s.dirs["intents"]
	if !ok {
		return ErrInvalid
	}
	f, e := createAt(dir, hexID(txn)+".bin")
	if e != nil {
		return e
	}
	if e = writeExact(f, raw[:]); e != nil {
		_ = f.Close()
		return ErrUncertain
	}
	if f.Sync() != nil {
		_ = f.Close()
		return ErrUncertain
	}
	if f.Close() != nil {
		return ErrUncertain
	}
	if s.syncFD(dir) != nil {
		return ErrUncertain
	}
	got, e := loadIntent(t, txn)
	if e != nil {
		return e
	}
	if got != raw {
		return ErrChanged
	}
	return nil
}
func loadIntent(t *Transaction, txn [16]byte) ([312]byte, error) {
	var raw [312]byte
	if txn == ([16]byte{}) {
		return raw, ErrInvalid
	}
	f, e := openNamed(t, "intents", hexID(txn)+".bin")
	if e != nil {
		return raw, e
	}
	before, e := statFile(f)
	if e != nil {
		_ = f.Close()
		return raw, e
	}
	if before.Size != 312 {
		_ = f.Close()
		return raw, ErrInvalid
	}
	if _, e = io.ReadFull(f, raw[:]); e != nil {
		_ = f.Close()
		return [312]byte{}, ErrUnavailable
	}
	after, x := statFile(f)
	if x != nil || after != before {
		_ = f.Close()
		return [312]byte{}, ErrChanged
	}
	if string(raw[:8]) != "SSAPCMT1" || string(raw[8:24]) != string(txn[:]) {
		_ = f.Close()
		return [312]byte{}, ErrInvalid
	}
	s, x := live(t)
	if x != nil {
		_ = f.Close()
		return [312]byte{}, x
	}
	dir, ok := s.dirs["intents"]
	if !ok || validDir(dir) != nil || f.Sync() != nil || unix.Fsync(dir) != nil {
		_ = f.Close()
		return [312]byte{}, ErrUncertain
	}
	if f.Close() != nil {
		return [312]byte{}, ErrUncertain
	}
	return raw, nil
}
func entries(t *Transaction, kind string, visit func(string) error) error {
	if visit == nil {
		return ErrInvalid
	}
	s, e := live(t)
	if e != nil {
		return e
	}
	fd, ok := s.dirs[kind]
	if !ok {
		return ErrInvalid
	}
	if e = validDir(fd); e != nil {
		return e
	}
	dup, x := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if x != nil {
		return ErrUnavailable
	}
	d := os.NewFile(uintptr(dup), "appstore-entries")
	defer d.Close()
	for {
		list, x := d.ReadDir(64)
		if x != nil && x != io.EOF {
			return ErrUnavailable
		}
		for _, entry := range list {
			name := entry.Name()
			if !canonicalName(kind, name) {
				return ErrInvalid
			}
			f, x := openNamed(t, kind, name)
			if x != nil {
				return x
			}
			if f.Close() != nil {
				return ErrUnavailable
			}
			if x = visit(name); x != nil {
				return x
			}
		}
		if x == io.EOF {
			return nil
		}
	}
}
func publish(t *Transaction, id [16]byte) error {
	if id == ([16]byte{}) {
		return ErrInvalid
	}
	s, e := live(t)
	if e != nil {
		return e
	}
	src, dst := s.dirs["candidates"], s.dirs["snapshots"]
	name := hexID(id) + ".bin"
	if !canonicalName("candidates", name) {
		return ErrInvalid
	}
	if e = validDir(src); e != nil {
		return e
	}
	if e = validDir(dst); e != nil {
		return e
	}
	x := unix.Renameat2(src, name, dst, name, unix.RENAME_NOREPLACE)
	if x != nil {
		if x == unix.ENOSYS || x == unix.EINVAL || x == unix.EOPNOTSUPP {
			return ErrUnsupported
		}
		return errno(x)
	}
	if unix.Fsync(src) != nil || unix.Fsync(dst) != nil {
		return ErrUncertain
	}
	return nil
}
