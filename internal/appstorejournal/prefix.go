package appstorejournal

import (
	"errors"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

type Prefix struct {
	store     [16]byte
	stateHash [32]byte
	head      [32]byte
	count     uint64
	parsed    bool
}

// InspectPrefix leaves any local suffix unread for separate reconciliation.
func InspectPrefix(expected appstoreanchorstate.State, r io.Reader) (Prefix, error) {
	return inspectPrefix(expected, r, nil)
}

var ErrReused = errors.New("application-store journal candidate ID already used")

// CheckFreshPair checks candidate IDs in this prefix only, not retained objects or authority.
func CheckFreshPair(expected appstoreanchorstate.State, r io.Reader, candidate Entry) (Prefix, error) {
	if !expected.Valid() || !candidate.Valid() || expected.JournalCount() >= appstoreanchorstate.MaxReservations || candidate.Index() != expected.JournalCount() {
		return Prefix{}, ErrInvalid
	}
	return inspectPrefix(expected, r, &candidate)
}

func inspectPrefix(expected appstoreanchorstate.State, r io.Reader, candidate *Entry) (Prefix, error) {
	if !expected.Valid() {
		return Prefix{}, ErrInvalid
	}
	if r == nil {
		return Prefix{}, ErrUnavailable
	}
	genesis, err := appstoreanchorstate.Genesis(expected.StoreID())
	if err != nil {
		return Prefix{}, ErrInvalid
	}
	head := genesis.JournalHead()
	reused := false
	var raw [Size]byte
	defer clear(raw[:])
	for index := uint64(0); index < expected.JournalCount(); index++ {
		if err := readExact(r, raw[:]); err != nil {
			return Prefix{}, err
		}
		entry, err := ParseEntry(raw[:], index)
		if err != nil {
			return Prefix{}, ErrInvalid
		}
		if candidate != nil && (entry.SnapshotID() == candidate.SnapshotID() || entry.TransactionID() == candidate.TransactionID() || entry.SnapshotID() == candidate.TransactionID() || entry.TransactionID() == candidate.SnapshotID()) {
			reused = true
		}
		head, err = NextHead(expected.StoreID(), head, entry)
		if err != nil {
			return Prefix{}, ErrInvalid
		}
	}
	if head != expected.JournalHead() {
		return Prefix{}, ErrInvalid
	}
	if reused {
		return Prefix{}, ErrReused
	}
	return Prefix{store: expected.StoreID(), stateHash: expected.Hash(), head: head, count: expected.JournalCount(), parsed: true}, nil
}

func readExact(r io.Reader, b []byte) error {
	for offset := 0; offset < len(b); {
		n, err := r.Read(b[offset:])
		if n < 0 || n > len(b)-offset {
			return ErrUnavailable
		}
		offset += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				if offset == len(b) {
					return nil
				}
				return ErrInvalid
			}
			return ErrUnavailable
		}
		if n == 0 {
			return ErrUnavailable
		}
	}
	return nil
}

// Valid describes commitment matching only, not authentication or uniqueness.
func (p Prefix) Valid() bool           { return p.parsed }
func (p Prefix) StoreID() [16]byte     { return p.store }
func (p Prefix) StateHash() [32]byte   { return p.stateHash }
func (p Prefix) Head() [32]byte        { return p.head }
func (p Prefix) Count() uint64         { return p.count }
func (p Prefix) ConsumedBytes() uint64 { return p.count * Size }
