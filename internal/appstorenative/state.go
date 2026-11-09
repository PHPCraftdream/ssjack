// Package appstorenative implements ciphertext records on protected native roots.
// Transaction operations require a held Begin lease, owned by appstorefile.
package appstorenative

import (
	"os"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

type Directory struct {
	mu     sync.Mutex
	root   *ownerfs.Root
	dirs   map[string]*ownerfs.Root
	closed bool
	tx     *Transaction
}

type Transaction struct {
	mu      sync.RWMutex
	writing sync.Mutex
	owner   *Directory
	unlock  func() error
	ended   bool
}

type Revision struct {
	Dev, Ino                                 uint64
	Size                                     int64
	MtimeSec, MtimeNsec, CtimeSec, CtimeNsec int64
}

func Open(file *os.File, store [16]byte) (*Directory, error) {
	if file == nil || store == ([16]byte{}) {
		return nil, ownerfs.ErrInvalid
	}
	root, err := ownerfs.Adopt(file)
	if err != nil {
		return nil, err
	}
	d := &Directory{root: root, dirs: make(map[string]*ownerfs.Root)}
	for _, name := range []string{"snapshots", "candidates", "recovery", "intents", "quarantine"} {
		d.dirs[name], err = root.Child(name, true)
		if err != nil {
			d.closeRoots()
			return nil, err
		}
	}
	return d, nil
}
func (d *Directory) closeRoots() error {
	var result error
	for _, root := range d.dirs {
		if root != nil {
			if err := root.Close(); err != nil && result == nil {
				result = err
			}
		}
	}
	d.dirs = nil
	if d.root != nil {
		if err := d.root.Close(); err != nil && result == nil {
			result = err
		}
		d.root = nil
	}
	return result
}
func (d *Directory) Identity() (uint64, uint64, error) {
	if d == nil {
		return 0, 0, ownerfs.ErrInvalid
	}
	if !d.mu.TryLock() {
		return 0, 0, ownerfs.ErrBusy
	}
	defer d.mu.Unlock()
	if d.closed {
		return 0, 0, ownerfs.ErrUnavailable
	}
	return d.root.Identity()
}
func (d *Directory) Close() error {
	if d == nil {
		return nil
	}
	if !d.mu.TryLock() {
		return ownerfs.ErrBusy
	}
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.closeRoots()
}
func (d *Directory) Lock() (*Transaction, error) {
	if d == nil {
		return nil, ownerfs.ErrInvalid
	}
	if !d.mu.TryLock() {
		return nil, ownerfs.ErrBusy
	}
	fail := func(err error) (*Transaction, error) { d.mu.Unlock(); return nil, err }
	if d.closed {
		return fail(ownerfs.ErrUnavailable)
	}
	if _, _, err := d.root.Identity(); err != nil {
		return fail(err)
	}
	for _, root := range d.dirs {
		if _, _, err := root.Identity(); err != nil {
			return fail(err)
		}
	}
	unlock, err := d.root.Lock()
	if err != nil {
		return fail(err)
	}
	t := &Transaction{owner: d, unlock: unlock}
	d.tx = t
	return t, nil
}
func (t *Transaction) live() (*Directory, error) {
	if t == nil || t.owner == nil || t.ended {
		return nil, ownerfs.ErrUnavailable
	}
	d := t.owner
	if d.closed || d.tx != t {
		return nil, ownerfs.ErrUnavailable
	}
	if _, _, err := d.root.Identity(); err != nil {
		return nil, err
	}
	return d, nil
}
func (t *Transaction) Begin() (func(), error) {
	if t == nil {
		return nil, ownerfs.ErrUnavailable
	}
	t.mu.RLock()
	if _, err := t.live(); err != nil {
		t.mu.RUnlock()
		return nil, err
	}
	return t.mu.RUnlock, nil
}
func (t *Transaction) mutation() (func(), error) {
	if !t.writing.TryLock() {
		return nil, ownerfs.ErrBusy
	}
	return t.writing.Unlock, nil
}
func (t *Transaction) Close() error {
	if t == nil {
		return nil
	}
	if !t.mu.TryLock() {
		return ownerfs.ErrBusy
	}
	defer t.mu.Unlock()
	if t.ended {
		return nil
	}
	d := t.owner
	if d == nil || d.tx != t {
		return ownerfs.ErrUnavailable
	}
	t.ended = true
	d.tx = nil
	err := t.unlock()
	d.mu.Unlock()
	return err
}
func (t *Transaction) directory(kind string) (*ownerfs.Root, error) {
	d, err := t.live()
	if err != nil {
		return nil, err
	}
	root := d.dirs[kind]
	if root == nil {
		return nil, ownerfs.ErrInvalid
	}
	if _, _, err := root.Identity(); err != nil {
		return nil, err
	}
	return root, nil
}
func (t *Transaction) Temporary() (*os.File, error) {
	release, err := t.mutation()
	if err != nil {
		return nil, err
	}
	defer release()
	d, err := t.live()
	if err != nil {
		return nil, err
	}
	return d.root.Temporary()
}
func Stat(file *os.File, anonymous bool) (Revision, error) {
	m, err := ownerfs.Stat(file, anonymous)
	if err != nil {
		return Revision{}, err
	}
	if m.Directory || m.Size < 0 {
		return Revision{}, ownerfs.ErrInvalid
	}
	return Revision{m.Dev, m.Ino, m.Size, m.MtimeSec, m.MtimeNsec, m.CtimeSec, m.CtimeNsec}, nil
}
