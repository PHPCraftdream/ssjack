// Package appstorefile provides fd-relative private ciphertext file operations.
// It makes no cryptographic, anchor, or power-loss durability claim.
package appstorefile

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
)

var (
	ErrInvalid     = errors.New("invalid application-store file")
	ErrUnsupported = errors.New("application-store file operations unsupported")
	ErrUnavailable = errors.New("application-store file operation unavailable")
	ErrBusy        = errors.New("application-store directory busy")
	ErrExists      = errors.New("application-store file exists")
	ErrMissing     = errors.New("application-store file missing")
	ErrChanged     = errors.New("application-store file changed")
	ErrUncertain   = errors.New("application-store file outcome uncertain")
)

type Directory struct{ state *directoryState }
type Transaction struct{ state *transactionState }
type Revision struct {
	Dev, Ino                                 uint64
	Size                                     int64
	MtimeSec, MtimeNsec, CtimeSec, CtimeNsec int64
}

func Open(root *os.File, store [16]byte) (*Directory, error) { return open(root, store) }
func (d *Directory) Lock() (*Transaction, error)             { return lock(d) }
func (d *Directory) StoreID() [16]byte {
	if d == nil || d.state == nil {
		return [16]byte{}
	}
	return d.state.store
}
func hexID(id [16]byte) string                         { return hex.EncodeToString(id[:]) }
func (d *Directory) Close() error                      { return closeDirectory(d) }
func (d *Directory) Identity() (uint64, uint64, error) { return directoryIdentity(d) }
func (t *Transaction) Close() error                    { return end(t) }
func (t *Transaction) Journal() (*os.File, error) {
	release, err := begin(t)
	if err != nil {
		return nil, err
	}
	defer release()
	return journal(t)
}
func (t *Transaction) AppendJournal(entry [40]byte, expectedCount uint64) error {
	return t.run(func() error { return appendJournal(t, entry, expectedCount) })
}
func (t *Transaction) SyncJournal() error {
	return t.run(func() error { return syncJournal(t) })
}
func (t *Transaction) Quarantine(snapshot [16]byte) error {
	return t.run(func() error { return quarantine(t, snapshot) })
}
func (t *Transaction) CreateCandidate(id [16]byte) (*os.File, error) {
	release, err := begin(t)
	if err != nil {
		return nil, err
	}
	defer release()
	return createCandidate(t, id)
}
func (t *Transaction) OpenCandidate(id [16]byte) (*os.File, error) {
	release, err := begin(t)
	if err != nil {
		return nil, err
	}
	defer release()
	return openNamed(t, "candidates", hexID(id)+".bin")
}
func (t *Transaction) OpenSnapshot(id [16]byte) (*os.File, error) {
	release, err := begin(t)
	if err != nil {
		return nil, err
	}
	defer release()
	return openNamed(t, "snapshots", hexID(id)+".bin")
}
func (t *Transaction) OpenRecovery(snapshot, txn [16]byte) (*os.File, error) {
	release, err := begin(t)
	if err != nil {
		return nil, err
	}
	defer release()
	return openNamed(t, "recovery", hexID(snapshot)+"-"+hexID(txn)+".bin")
}
func (t *Transaction) SyncCandidate(id [16]byte) error {
	return t.run(func() error { return syncCandidate(t, id) })
}
func (t *Transaction) Retain(ctx context.Context, snapshot, txn [16]byte, source *os.File, expected [32]byte, limit uint64) error {
	return t.run(func() error { return retain(t, ctx, snapshot, txn, source, expected, limit) })
}
func (t *Transaction) CreateIntent(txn [16]byte, raw [312]byte) error {
	return t.run(func() error { return createIntent(t, txn, raw) })
}
func (t *Transaction) LoadIntent(txn [16]byte) ([312]byte, error) {
	release, err := begin(t)
	if err != nil {
		return [312]byte{}, err
	}
	defer release()
	return loadIntent(t, txn)
}
func (t *Transaction) Entries(kind string, visit func(string) error) error {
	return t.run(func() error { return entries(t, kind, visit) })
}
func (t *Transaction) OpenNamed(kind, name string) (*os.File, error) {
	release, err := begin(t)
	if err != nil {
		return nil, err
	}
	defer release()
	return openNamed(t, kind, name)
}
func (t *Transaction) Publish(id [16]byte) error {
	return t.run(func() error { return publish(t, id) })
}
func (t *Transaction) Pointer(tuple [64]byte) error {
	return t.run(func() error { return pointer(t, tuple) })
}
func (t *Transaction) ReadPointer() ([64]byte, error) {
	release, err := begin(t)
	if err != nil {
		return [64]byte{}, err
	}
	defer release()
	return readPointer(t)
}
func (t *Transaction) run(op func() error) error {
	release, err := begin(t)
	if err != nil {
		return err
	}
	defer release()
	return op()
}

// Temporary creates an anonymous, exclusively locked ciphertext spool with no named fallback.
func (t *Transaction) Temporary() (*os.File, error) {
	release, err := begin(t)
	if err != nil {
		return nil, err
	}
	defer release()
	return temporary(t)
}

func StatTemporary(f *os.File) (Revision, error) { return statTemporary(f) }
func Stat(f *os.File) (Revision, error)          { return statFile(f) }
func Hash(ctx context.Context, f *os.File, limit uint64) ([32]byte, error) {
	return hashFile(ctx, f, limit)
}
