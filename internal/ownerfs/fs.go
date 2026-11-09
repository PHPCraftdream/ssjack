// Package ownerfs owns protected native ciphertext filesystem capabilities.
// It does not promise power-loss durability or expose model-facing file access.
package ownerfs

import (
	"errors"
	"os"
	"strings"
	"sync"
)

var (
	ErrInvalid     = errors.New("invalid protected owner filesystem object")
	ErrUnavailable = errors.New("protected owner filesystem operation unavailable")
	ErrUnsupported = errors.New("protected owner filesystem operation unsupported")
	ErrBusy        = errors.New("protected owner filesystem object busy")
	ErrExists      = errors.New("protected owner filesystem object exists")
	ErrMissing     = errors.New("protected owner filesystem object missing")
	ErrChanged     = errors.New("protected owner filesystem object changed")
	ErrUncertain   = errors.New("protected owner filesystem outcome uncertain")
)

type Metadata struct {
	Dev, Ino, Links                          uint64
	Size                                     int64
	MtimeSec, MtimeNsec, CtimeSec, CtimeNsec int64
	Directory                                bool
}

// Root owns one protected directory handle, not ambient path access.
type Root struct {
	mu     sync.RWMutex
	file   *os.File
	closed bool
}

func atom(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 128 {
		return false
	}
	for _, b := range []byte(name) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("._-", rune(b))) {
			return false
		}
	}
	return true
}
func Open(path string) (*Root, error)                      { return openRoot(path) }
func Adopt(file *os.File) (*Root, error)                   { return adoptRoot(file) }
func MakeRoot(path string) (*Root, error)                  { return makeRoot(path) }
func Stat(file *os.File, anonymous bool) (Metadata, error) { return stat(file, anonymous) }

func (r *Root) use() (func(), error) {
	if r == nil {
		return nil, ErrInvalid
	}
	r.mu.RLock()
	if r.closed || r.file == nil {
		r.mu.RUnlock()
		return nil, ErrUnavailable
	}
	metadata, err := stat(r.file, false)
	if err != nil || !metadata.Directory {
		r.mu.RUnlock()
		return nil, ErrInvalid
	}
	return r.mu.RUnlock, nil
}
func (r *Root) Close() error {
	if r == nil {
		return nil
	}
	if !r.mu.TryLock() {
		return ErrBusy
	}
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.file == nil {
		return nil
	}
	return r.file.Close()
}
func (r *Root) Identity() (uint64, uint64, error) {
	release, err := r.use()
	if err != nil {
		return 0, 0, err
	}
	defer release()
	metadata, err := stat(r.file, false)
	return metadata.Dev, metadata.Ino, err
}
func (r *Root) File() (*os.File, error) {
	release, err := r.use()
	if err != nil {
		return nil, err
	}
	defer release()
	return duplicate(r.file)
}
func (r *Root) Child(name string, create bool) (*Root, error) {
	if !atom(name) {
		return nil, ErrInvalid
	}
	release, err := r.use()
	if err != nil {
		return nil, err
	}
	defer release()
	return child(r.file, name, create)
}
func (r *Root) Read(name string) (*os.File, error) {
	if !atom(name) {
		return nil, ErrInvalid
	}
	release, err := r.use()
	if err != nil {
		return nil, err
	}
	defer release()
	return openFile(r.file, name, false, false)
}
func (r *Root) Write(name string, exclusive bool) (*os.File, error) {
	if !atom(name) {
		return nil, ErrInvalid
	}
	release, err := r.use()
	if err != nil {
		return nil, err
	}
	defer release()
	return openFile(r.file, name, true, exclusive)
}
func (r *Root) Temporary() (*os.File, error) {
	release, err := r.use()
	if err != nil {
		return nil, err
	}
	defer release()
	return temporary(r.file)
}
func (r *Root) Remove(name string) error {
	if !atom(name) {
		return ErrInvalid
	}
	release, err := r.use()
	if err != nil {
		return err
	}
	defer release()
	return remove(r.file, name)
}
func (r *Root) Flush(name string) error {
	if !atom(name) {
		return ErrInvalid
	}
	release, err := r.use()
	if err != nil {
		return err
	}
	defer release()
	return flush(r.file, name)
}
func (r *Root) Entries(visit func(string) error) error {
	if visit == nil {
		return ErrInvalid
	}
	release, err := r.use()
	if err != nil {
		return err
	}
	defer release()
	return entries(r.file, visit)
}
func (r *Root) Lock() (func() error, error) { return r.LockName(".files.lock") }
func (r *Root) LockName(name string) (func() error, error) {
	if !atom(name) {
		return nil, ErrInvalid
	}
	release, err := r.use()
	if err != nil {
		return nil, err
	}
	defer release()
	return lock(r.file, name)
}

// Rename never changes roots through path resolution. Replacement is explicit.
func (r *Root) Rename(name string, destination *Root, target string, replace bool) error {
	if !atom(name) || !atom(target) || destination == nil {
		return ErrInvalid
	}
	release, err := r.use()
	if err != nil {
		return err
	}
	defer release()
	if r != destination {
		other, err := destination.use()
		if err != nil {
			return err
		}
		defer other()
	}
	return rename(r.file, name, destination.file, target, replace)
}
