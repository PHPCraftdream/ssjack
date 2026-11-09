//go:build !linux

package appstorefile

import (
	"context"
	"encoding/hex"
	"errors"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/appstorenative"
	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

type directoryState struct {
	store  [16]byte
	native *appstorenative.Directory
}
type transactionState struct{ native *appstorenative.Transaction }

func nativeError(err error) error {
	for _, pair := range [][2]error{
		{ownerfs.ErrInvalid, ErrInvalid}, {ownerfs.ErrUnsupported, ErrUnsupported},
		{ownerfs.ErrUnavailable, ErrUnavailable}, {ownerfs.ErrBusy, ErrBusy},
		{ownerfs.ErrExists, ErrExists}, {ownerfs.ErrMissing, ErrMissing},
		{ownerfs.ErrChanged, ErrChanged}, {ownerfs.ErrUncertain, ErrUncertain},
	} {
		if errors.Is(err, pair[0]) {
			return pair[1]
		}
	}
	return err
}
func open(root *os.File, store [16]byte) (*Directory, error) {
	native, err := appstorenative.Open(root, store)
	if err != nil {
		return nil, nativeError(err)
	}
	return &Directory{state: &directoryState{store: store, native: native}}, nil
}
func directoryIdentity(d *Directory) (uint64, uint64, error) {
	if d == nil || d.state == nil {
		return 0, 0, ErrInvalid
	}
	dev, ino, err := d.state.native.Identity()
	return dev, ino, nativeError(err)
}
func closeDirectory(d *Directory) error {
	if d == nil || d.state == nil {
		return nil
	}
	return nativeError(d.state.native.Close())
}
func lock(d *Directory) (*Transaction, error) {
	if d == nil || d.state == nil {
		return nil, ErrInvalid
	}
	tx, err := d.state.native.Lock()
	if err != nil {
		return nil, nativeError(err)
	}
	return &Transaction{state: &transactionState{native: tx}}, nil
}
func begin(t *Transaction) (func(), error) {
	if t == nil || t.state == nil {
		return nil, ErrUnavailable
	}
	release, err := t.state.native.Begin()
	return release, nativeError(err)
}
func end(t *Transaction) error {
	if t == nil || t.state == nil {
		return nil
	}
	return nativeError(t.state.native.Close())
}
func journal(t *Transaction) (*os.File, error) {
	file, err := t.state.native.Journal()
	return file, nativeError(err)
}
func appendJournal(t *Transaction, raw [40]byte, count uint64) error {
	return nativeError(t.state.native.AppendJournal(raw, count))
}
func syncJournal(t *Transaction) error { return nativeError(t.state.native.SyncJournal()) }
func createCandidate(t *Transaction, id [16]byte) (*os.File, error) {
	file, err := t.state.native.CreateCandidate(id)
	return file, nativeError(err)
}
func openNamed(t *Transaction, kind, name string) (*os.File, error) {
	file, err := t.state.native.OpenNamed(kind, name)
	return file, nativeError(err)
}
func syncCandidate(t *Transaction, id [16]byte) error {
	return nativeError(t.state.native.SyncCandidate(id))
}
func quarantine(t *Transaction, id [16]byte) error { return nativeError(t.state.native.Quarantine(id)) }
func publish(t *Transaction, id [16]byte) error    { return nativeError(t.state.native.Publish(id)) }
func createIntent(t *Transaction, id [16]byte, raw [312]byte) error {
	return nativeError(t.state.native.CreateIntent(id, raw))
}
func loadIntent(t *Transaction, id [16]byte) ([312]byte, error) {
	raw, err := t.state.native.LoadIntent(id)
	return raw, nativeError(err)
}
func entries(t *Transaction, kind string, visit func(string) error) error {
	return nativeError(t.state.native.Entries(kind, visit))
}
func pointer(t *Transaction, tuple [64]byte) error { return nativeError(t.state.native.Pointer(tuple)) }
func readPointer(t *Transaction) ([64]byte, error) {
	raw, err := t.state.native.ReadPointer()
	return raw, nativeError(err)
}
func temporary(t *Transaction) (*os.File, error) {
	file, err := t.state.native.Temporary()
	return file, nativeError(err)
}
func statFile(file *os.File) (Revision, error) {
	revision, err := appstorenative.Stat(file, false)
	return Revision(revision), nativeError(err)
}
func statTemporary(file *os.File) (Revision, error) {
	revision, err := appstorenative.Stat(file, true)
	return Revision(revision), nativeError(err)
}
func hashFile(ctx context.Context, file *os.File, limit uint64) ([32]byte, error) {
	digest, err := appstorenative.Hash(ctx, file, limit)
	return digest, nativeError(err)
}
func retain(t *Transaction, ctx context.Context, snapshot, txn [16]byte, source *os.File, expected [32]byte, limit uint64) error {
	return nativeError(t.state.native.Retain(ctx, snapshot, txn, source, expected, limit))
}
func fmtHex(raw []byte) string { return hex.EncodeToString(raw) }
