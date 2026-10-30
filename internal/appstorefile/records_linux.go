//go:build linux

package appstorefile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func fmtHex(b []byte) string { return hex.EncodeToString(b) }

func fileFD(f *os.File) (unix.Stat_t, error) {
	var s unix.Stat_t
	if f == nil || unix.Fstat(int(f.Fd()), &s) != nil {
		return s, ErrInvalid
	}
	if s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&07777 != 0600 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 || s.Size < 0 {
		return s, ErrInvalid
	}
	return s, nil
}
func rev(s unix.Stat_t) Revision {
	return Revision{uint64(s.Dev), s.Ino, s.Size, s.Mtim.Sec, s.Mtim.Nsec, s.Ctim.Sec, s.Ctim.Nsec}
}
func statFile(f *os.File) (Revision, error) { s, e := fileFD(f); return rev(s), e }

func hashFile(ctx context.Context, f *os.File, limit uint64) ([32]byte, error) {
	var z [32]byte
	if ctx == nil {
		return z, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return z, e
	}
	s, e := fileFD(f)
	if e != nil {
		return z, e
	}
	if limit > 1<<42 || uint64(s.Size) > limit {
		return z, ErrInvalid
	}
	before := rev(s)
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return z, ErrUnavailable
	}
	h := sha256.New()
	r := io.LimitReader(f, s.Size+1)
	buf := make([]byte, 65536)
	var nread int64
	for {
		if e = ctx.Err(); e != nil {
			return z, e
		}
		n, x := r.Read(buf)
		if n > 0 {
			nread += int64(n)
			if nread > s.Size {
				return z, ErrChanged
			}
			_, _ = h.Write(buf[:n])
		}
		if x == io.EOF {
			break
		}
		if x != nil {
			return z, ErrUnavailable
		}
	}
	if nread != s.Size {
		return z, ErrChanged
	}
	after, e := statFile(f)
	if e != nil || after != before {
		return z, ErrChanged
	}
	copy(z[:], h.Sum(nil))
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return [32]byte{}, ErrUnavailable
	}
	return z, nil
}

func openNamed(t *Transaction, kind, name string) (*os.File, error) {
	s, e := live(t)
	if e != nil {
		return nil, e
	}
	fd, ok := s.dirs[kind]
	if !ok || !canonicalName(kind, name) {
		return nil, ErrInvalid
	}
	if e = validDir(fd); e != nil {
		return nil, e
	}
	n, x := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if x != nil {
		return nil, errno(x)
	}
	f := os.NewFile(uintptr(n), "appstore-ciphertext")
	if _, x = fileFD(f); x != nil {
		f.Close()
		return nil, x
	}
	return f, nil
}
func journal(t *Transaction) (*os.File, error) {
	s, e := live(t)
	if e != nil {
		return nil, e
	}
	fd, x := unix.Openat(s.fd, "journal.bin", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	created := false
	var createdStat unix.Stat_t
	if x == unix.ENOENT {
		fd, x = unix.Openat(s.fd, "journal.bin", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if x == nil {
			created = true
			if unix.Fstat(fd, &createdStat) != nil || createdStat.Mode&unix.S_IFMT != unix.S_IFREG {
				unix.Close(fd)
				return nil, ErrInvalid
			}
			if unix.Fsync(fd) != nil || unix.Fsync(s.fd) != nil {
				unix.Close(fd)
				return nil, ErrUncertain
			}
			if unix.Close(fd) != nil {
				return nil, ErrUnavailable
			}
			fd, x = unix.Openat(s.fd, "journal.bin", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if x != nil {
				return nil, ErrUncertain
			}
		}
	}
	if x != nil {
		return nil, errno(x)
	}
	f := os.NewFile(uintptr(fd), "appstore-journal")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Size < 0 || st.Size > 40*(1<<20) || st.Size%40 != 0 || (created && (st.Dev != createdStat.Dev || st.Ino != createdStat.Ino)) {
		f.Close()
		return nil, ErrInvalid
	}
	return f, nil
}
func appendJournal(t *Transaction, entry [40]byte, count uint64) error {
	if count >= 1<<20 || binary.BigEndian.Uint64(entry[:8]) != count {
		return ErrInvalid
	}
	zero := true
	for _, b := range entry[8:24] {
		if b != 0 {
			zero = false
		}
	}
	if zero {
		return ErrInvalid
	}
	zero = true
	for _, b := range entry[24:40] {
		if b != 0 {
			zero = false
		}
	}
	if zero {
		return ErrInvalid
	}
	f, e := journal(t)
	if e != nil {
		return e
	}
	defer f.Close()
	s, e := live(t)
	if e != nil {
		return e
	}
	st, x := fileFD(f)
	if x != nil {
		return x
	}
	if uint64(st.Size) != count*40 {
		return ErrChanged
	}
	wfd, x := unix.Openat(s.fd, "journal.bin", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if x != nil {
		return errno(x)
	}
	var writableStat unix.Stat_t
	if unix.Fstat(wfd, &writableStat) != nil || writableStat.Dev != st.Dev || writableStat.Ino != st.Ino || writableStat.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(wfd)
		return ErrChanged
	}
	if n, x := unix.Pwrite(int(wfd), entry[:], int64(count*40)); x != nil || n != len(entry) {
		unix.Close(wfd)
		return ErrUncertain
	}
	if unix.Fsync(wfd) != nil || unix.Fsync(s.fd) != nil {
		unix.Close(wfd)
		return ErrUncertain
	}
	var got [40]byte
	if n, x := f.ReadAt(got[:], int64(count*40)); x != nil || n != len(got) || got != entry {
		unix.Close(wfd)
		return ErrUncertain
	}
	if unix.Close(wfd) != nil {
		return ErrUnavailable
	}
	return nil
}
func createCandidate(t *Transaction, id [16]byte) (*os.File, error) {
	if id == ([16]byte{}) {
		return nil, ErrInvalid
	}
	s, e := live(t)
	if e != nil {
		return nil, e
	}
	fd, ok := s.dirs["candidates"]
	if !ok {
		return nil, ErrInvalid
	}
	x := validDir(fd)
	if x != nil {
		return nil, x
	}
	n, x := unix.Openat(fd, fmtHex(id[:])+".bin", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if x != nil {
		return nil, errno(x)
	}
	f := os.NewFile(uintptr(n), "appstore-candidate")
	if _, x = fileFD(f); x != nil {
		f.Close()
		return nil, x
	}
	return f, nil
}
func syncCandidate(t *Transaction, id [16]byte) error {
	if id == ([16]byte{}) {
		return ErrInvalid
	}
	f, e := openNamed(t, "candidates", fmtHex(id[:])+".bin")
	if e != nil {
		return e
	}
	before, e := statFile(f)
	if e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return ErrUncertain
	}
	s, e := live(t)
	if e != nil {
		f.Close()
		return e
	}
	if unix.Fsync(s.dirs["candidates"]) != nil {
		f.Close()
		return ErrUncertain
	}
	after, e := statFile(f)
	ce := f.Close()
	if e != nil {
		return e
	}
	if before != after {
		return ErrChanged
	}
	if ce != nil {
		return ErrUnavailable
	}
	return nil
}
