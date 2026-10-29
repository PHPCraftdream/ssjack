// Package appstoreanchorstate checks state encoding without establishing authority.
package appstoreanchorstate

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const Size = 192
const MaxReservations = 1 << 20

var ErrInvalid = errors.New("invalid application-store anchor state")

type State struct {
	raw      [Size]byte
	sequence uint64
	count    uint64
	hash     [32]byte
	parsed   bool
}

// Parse checks canonical fields and expected scope, not a signed service reply.
func Parse(raw []byte, expectedStore [16]byte) (State, error) {
	if len(raw) != Size || expectedStore == ([16]byte{}) {
		return State{}, ErrInvalid
	}
	var s State
	copy(s.raw[:], raw)
	b := s.raw[:]
	if string(b[:4]) != "SSAS" || binary.BigEndian.Uint16(b[4:6]) != 1 || !zero(b[6:8]) || !zero(b[136:192]) || [16]byte(b[8:24]) != expectedStore {
		return State{}, ErrInvalid
	}
	sequence, count := binary.BigEndian.Uint64(b[24:32]), binary.BigEndian.Uint64(b[96:104])
	if count > MaxReservations || sequence > count {
		return State{}, ErrInvalid
	}
	noSnapshot, noFile, noTransaction := zero(b[32:48]), zero(b[48:80]), zero(b[80:96])
	if sequence == 0 {
		if !noSnapshot || !noFile || !noTransaction {
			return State{}, ErrInvalid
		}
	} else if noSnapshot || noFile || noTransaction {
		return State{}, ErrInvalid
	}
	head := [32]byte(b[104:136])
	genesis := genesisHead(expectedStore)
	if head == ([32]byte{}) || (count == 0 && head != genesis) || (count > 0 && head == genesis) {
		return State{}, ErrInvalid
	}
	s.sequence, s.count, s.parsed = sequence, count, true
	s.hash = sha256.Sum256(append([]byte("SSAPP-ANCHOR-STATE-v1"), b...))
	return s, nil
}

// Genesis constructs canonical bytes only; it never enrolls or creates a store.
func Genesis(store [16]byte) (State, error) {
	if store == ([16]byte{}) {
		return State{}, ErrInvalid
	}
	var raw [Size]byte
	copy(raw[:4], "SSAS")
	binary.BigEndian.PutUint16(raw[4:6], 1)
	copy(raw[8:24], store[:])
	head := genesisHead(store)
	copy(raw[104:136], head[:])
	return Parse(raw[:], store)
}

func genesisHead(store [16]byte) [32]byte {
	return sha256.Sum256(append([]byte("SSAPP-JOURNAL-GENESIS-v1"), store[:]...))
}

func zero(value []byte) bool {
	var bits byte
	for _, b := range value {
		bits |= b
	}
	return bits == 0
}

func (s State) Valid() bool                      { return s.parsed }
func (s State) Bytes() [Size]byte                { return s.raw }
func (s State) StoreID() [16]byte                { return [16]byte(s.raw[8:24]) }
func (s State) Sequence() uint64                 { return s.sequence }
func (s State) JournalCount() uint64             { return s.count }
func (s State) JournalHead() [32]byte            { return [32]byte(s.raw[104:136]) }
func (s State) Hash() [32]byte                   { return s.hash }
func (s State) CommittedSnapshotID() [16]byte    { return [16]byte(s.raw[32:48]) }
func (s State) CommittedFileHash() [32]byte      { return [32]byte(s.raw[48:80]) }
func (s State) CommittedTransactionID() [16]byte { return [16]byte(s.raw[80:96]) }
