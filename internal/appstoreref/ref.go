// Package appstoreref provides exact references, not secret access capabilities.
package appstoreref

import (
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
)

var ErrInvalid = errors.New("invalid application-store reference or catalog metadata")
var ErrScope = errors.New("application-store reference scope mismatch")
var ErrNotFound = errors.New("exact application-store reference metadata not found")

type Ref struct {
	store    [16]byte
	object   [16]byte
	version  [16]byte
	snapshot [16]byte
}

// New requires all four IDs; it never selects a current snapshot or version.
func New(store, object, version, snapshot [16]byte) (Ref, error) {
	r := Ref{store: store, object: object, version: version, snapshot: snapshot}
	if !r.Valid() {
		return Ref{}, ErrInvalid
	}
	return r, nil
}

func (r Ref) Valid() bool {
	zero := [16]byte{}
	return r.store != zero && r.object != zero && r.version != zero && r.snapshot != zero
}
func (r Ref) StoreID() [16]byte    { return r.store }
func (r Ref) ObjectID() [16]byte   { return r.object }
func (r Ref) VersionID() [16]byte  { return r.version }
func (r Ref) SnapshotID() [16]byte { return r.snapshot }

// FindMetadata matches untrusted catalog metadata, never bytes or authority.
func FindMetadata(r Ref, catalog appstorecatalog.Catalog) (appstorecatalog.Entry, error) {
	if !r.Valid() || !catalog.Valid() {
		return appstorecatalog.Entry{}, ErrInvalid
	}
	if r.store != catalog.StoreID() || r.snapshot != catalog.SnapshotID() {
		return appstorecatalog.Entry{}, ErrScope
	}
	for _, entry := range catalog.Entries() {
		if r.object == entry.ObjectID() && r.version == entry.VersionID() {
			return entry, nil
		}
	}
	return appstorecatalog.Entry{}, ErrNotFound
}
