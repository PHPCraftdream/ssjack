//go:build linux

package appstorefile

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type directoryState struct {
	mu     sync.Mutex
	fd     int
	dirs   map[string]int
	store  [16]byte
	closed bool
	fenced bool
	syncFD func(int) error
	tx     *transactionState
}
type transactionState struct {
	owner *directoryState
	ended bool
	mu    sync.RWMutex
}

func temporary(t *Transaction) (*os.File, error) {
	s, err := live(t)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(s.fd, ".", unix.O_TMPFILE|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENOSYS) {
			return nil, ErrUnsupported
		}
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "appstore-private-ciphertext")
	if _, err = statTemporary(f); err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		_ = f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}

func statTemporary(f *os.File) (Revision, error) {
	var st unix.Stat_t
	if f == nil || unix.Fstat(int(f.Fd()), &st) != nil {
		return Revision{}, ErrUnavailable
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 0 || st.Size < 0 {
		return Revision{}, ErrInvalid
	}
	return rev(st), nil
}

func validDir(fd int) error {
	var s unix.Stat_t
	if e := unix.Fstat(fd, &s); e != nil {
		return ErrUnavailable
	}
	if s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Mode&07777 != 0700 || s.Uid != uint32(os.Geteuid()) || s.Nlink == 0 {
		return ErrInvalid
	}
	return nil
}
func open(root *os.File, store [16]byte) (*Directory, error) {
	if root == nil || store == ([16]byte{}) {
		return nil, ErrInvalid
	}
	var a, b unix.Stat_t
	if unix.Fstat(int(root.Fd()), &a) != nil || a.Mode&unix.S_IFMT != unix.S_IFDIR || a.Mode&07777 != 0700 || a.Uid != uint32(os.Geteuid()) || a.Nlink == 0 {
		return nil, ErrInvalid
	}
	fd, e := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	if unix.Fstat(fd, &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino {
		unix.Close(fd)
		return nil, ErrInvalid
	}
	s := &directoryState{fd: fd, store: store, dirs: map[string]int{}, syncFD: unix.Fsync}
	for _, n := range []string{"snapshots", "candidates", "recovery", "intents", "quarantine"} {
		if e = unix.Mkdirat(fd, n, 0700); e != nil && !errors.Is(e, unix.EEXIST) {
			s.closeFDs()
			return nil, ErrUnavailable
		}
		c, x := unix.Openat(fd, n, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if x != nil {
			s.closeFDs()
			return nil, ErrInvalid
		}
		if x = validDir(c); x != nil {
			unix.Close(c)
			s.closeFDs()
			return nil, x
		}
		s.dirs[n] = c
	}
	if e = unix.Fsync(fd); e != nil {
		s.closeFDs()
		return nil, ErrUnavailable
	}
	return &Directory{state: s}, nil
}
func (s *directoryState) closeFDs() {
	for _, fd := range s.dirs {
		_ = unix.Close(fd)
	}
	s.dirs = nil
	if s.fd >= 0 {
		_ = unix.Close(s.fd)
		s.fd = -1
	}
}
func directoryIdentity(d *Directory) (uint64, uint64, error) {
	if d == nil || d.state == nil {
		return 0, 0, ErrInvalid
	}
	s := d.state
	if !s.mu.TryLock() {
		return 0, 0, ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return 0, 0, ErrUnavailable
	}
	if err := validDir(s.fd); err != nil {
		return 0, 0, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(s.fd, &st); err != nil {
		return 0, 0, ErrUnavailable
	}
	return uint64(st.Dev), st.Ino, nil
}

func closeDirectory(d *Directory) error {
	if d == nil || d.state == nil {
		return nil
	}
	s := d.state
	if !s.mu.TryLock() {
		return ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.closeFDs()
	return nil
}
func lock(d *Directory) (*Transaction, error) {
	if d == nil || d.state == nil {
		return nil, ErrInvalid
	}
	s := d.state
	if !s.mu.TryLock() {
		return nil, ErrBusy
	}
	if s.closed {
		s.mu.Unlock()
		return nil, ErrUnavailable
	}
	if s.fenced {
		s.mu.Unlock()
		return nil, ErrUncertain
	}
	for _, fd := range s.dirs {
		if e := validDir(fd); e != nil {
			s.mu.Unlock()
			return nil, e
		}
	}
	if e := validDir(s.fd); e != nil {
		s.mu.Unlock()
		return nil, e
	}
	if e := unix.Flock(s.fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		s.mu.Unlock()
		if errors.Is(e, unix.EWOULDBLOCK) || errors.Is(e, unix.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, ErrUnavailable
	}
	t := &transactionState{owner: s}
	s.tx = t
	return &Transaction{state: t}, nil
}
func begin(t *Transaction) (func(), error) {
	if t == nil || t.state == nil {
		return nil, ErrUnavailable
	}
	t.state.mu.RLock()
	if _, e := live(t); e != nil {
		t.state.mu.RUnlock()
		return nil, e
	}
	return t.state.mu.RUnlock, nil
}
func live(t *Transaction) (*directoryState, error) {
	if t == nil || t.state == nil || t.state.owner == nil {
		return nil, ErrUnavailable
	}
	s := t.state.owner
	if t.state.ended || s.closed || s.tx != t.state {
		return nil, ErrUnavailable
	}
	if e := validDir(s.fd); e != nil {
		return nil, e
	}
	return s, nil
}
func end(t *Transaction) error {
	if t == nil || t.state == nil {
		return nil
	}
	s := t.state.owner
	if s == nil {
		return nil
	}
	if !t.state.mu.TryLock() {
		return ErrBusy
	}
	defer t.state.mu.Unlock()
	if t.state.ended {
		return nil
	}
	if s.tx != t.state {
		return ErrUnavailable
	}
	t.state.ended = true
	s.tx = nil
	e := unix.Flock(s.fd, unix.LOCK_UN)
	s.mu.Unlock()
	return mapErr(e)
}
func mapErr(e error) error {
	if e == nil {
		return nil
	}
	return ErrUnavailable
}
