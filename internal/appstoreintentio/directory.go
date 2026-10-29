// Package appstoreintentio persists intent metadata, not secrets or replay authority.
package appstoreintentio

import (
	"errors"
	"os"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
)

var ErrInvalid = errors.New("invalid application-store intent metadata")
var ErrUnavailable = errors.New("application-store intent IO unavailable")
var ErrUnsupported = errors.New("application-store intent IO unsupported on this platform")
var ErrExists = errors.New("application-store intent already exists")
var ErrNotFound = errors.New("application-store intent not found")
var ErrBusy = errors.New("application-store intent directory busy")
var ErrClosed = errors.New("application-store intent directory closed")

type directoryState struct {
	mu       sync.Mutex
	fd       int
	store    [16]byte
	closed   bool
	syncFile func(int) error
}

type Directory struct{ state *directoryState }

// New owns an independent directory description; supplied provenance is the caller's responsibility.
func New(directory *os.File, store [16]byte) (*Directory, error) {
	return newDirectory(directory, store)
}

// Create never overwrites or deletes. Any failure may leave a record requiring reconciliation.
func (d *Directory) Create(intent appstoreanchorrequest.Intent) error {
	if !intent.Valid() {
		return ErrInvalid
	}
	request, ok := intent.Request()
	if !ok {
		return ErrInvalid
	}
	return d.run(func(s *directoryState) error {
		if request.StoreID() != s.store {
			return ErrInvalid
		}
		return create(s, intent.Bytes())
	})
}

// Load checks existing bytes only; it does not prove original publication or permit CAS.
func (d *Directory) Load(transaction [16]byte) (appstoreanchorrequest.Intent, error) {
	if transaction == ([16]byte{}) {
		return appstoreanchorrequest.Intent{}, ErrInvalid
	}
	var intent appstoreanchorrequest.Intent
	err := d.run(func(s *directoryState) error {
		raw, err := readRaw(s, transaction)
		if err != nil {
			return err
		}
		defer clear(raw[:])
		parsed, err := appstoreanchorrequest.ParseIntent(raw[:], s.store)
		if err != nil || [16]byte(raw[8:24]) != transaction {
			return ErrInvalid
		}
		intent = parsed
		return nil
	})
	if err != nil {
		return appstoreanchorrequest.Intent{}, err
	}
	return intent, nil
}

func (d *Directory) run(operation func(*directoryState) error) error {
	if d == nil || d.state == nil {
		return ErrClosed
	}
	s := d.state
	if !s.mu.TryLock() {
		return ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := lockDirectory(s); err != nil {
		return err
	}
	defer unlockDirectory(s)
	return operation(s)
}

func (d *Directory) Close() error {
	if d == nil || d.state == nil {
		return nil
	}
	s := d.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := closeDirectory(s)
	s.fd = -1
	return err
}
