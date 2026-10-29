// Package appstorejournal checks journal commitments, not reservation authority.
package appstorejournal

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

const Size = 40

var ErrInvalid = errors.New("invalid application-store journal prefix")
var ErrUnavailable = errors.New("application-store journal read unavailable")

type Entry struct {
	raw    [Size]byte
	parsed bool
}

func ParseEntry(raw []byte, expectedIndex uint64) (Entry, error) {
	if len(raw) != Size || expectedIndex >= appstoreanchorstate.MaxReservations {
		return Entry{}, ErrInvalid
	}
	var e Entry
	copy(e.raw[:], raw)
	if binary.BigEndian.Uint64(e.raw[:8]) != expectedIndex || [16]byte(e.raw[8:24]) == ([16]byte{}) || [16]byte(e.raw[24:40]) == ([16]byte{}) {
		return Entry{}, ErrInvalid
	}
	e.parsed = true
	return e, nil
}

// NewEntry constructs bytes only; it does not append, sync, reserve or generate IDs.
func NewEntry(index uint64, snapshot, transaction [16]byte) (Entry, error) {
	var raw [Size]byte
	binary.BigEndian.PutUint64(raw[:8], index)
	copy(raw[8:24], snapshot[:])
	copy(raw[24:40], transaction[:])
	return ParseEntry(raw[:], index)
}

func NextHead(store [16]byte, previous [32]byte, entry Entry) ([32]byte, error) {
	if store == ([16]byte{}) || previous == ([32]byte{}) || !entry.Valid() {
		return [32]byte{}, ErrInvalid
	}
	const domain = "SSAPP-JOURNAL-ENTRY-v1"
	var message [len(domain) + 16 + 32 + Size]byte
	copy(message[:], domain)
	copy(message[len(domain):], store[:])
	copy(message[len(domain)+16:], previous[:])
	copy(message[len(domain)+16+32:], entry.raw[:])
	head := sha256.Sum256(message[:])
	if head == ([32]byte{}) {
		return [32]byte{}, ErrInvalid
	}
	return head, nil
}

func (e Entry) Valid() bool             { return e.parsed }
func (e Entry) Bytes() [Size]byte       { return e.raw }
func (e Entry) Index() uint64           { return binary.BigEndian.Uint64(e.raw[:8]) }
func (e Entry) SnapshotID() [16]byte    { return [16]byte(e.raw[8:24]) }
func (e Entry) TransactionID() [16]byte { return [16]byte(e.raw[24:40]) }
