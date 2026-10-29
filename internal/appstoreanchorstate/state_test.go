package appstoreanchorstate_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

func store(value byte) [16]byte { return [16]byte(bytes.Repeat([]byte{value}, 16)) }

func genesisWire() []byte {
	s := store(1)
	head := sha256.Sum256(append([]byte("SSAPP-JOURNAL-GENESIS-v1"), s[:]...))
	literal := "5353415300010000" + strings.Repeat("01", 16) + strings.Repeat("00", 80) + hex.EncodeToString(head[:]) + strings.Repeat("00", 56)
	b, _ := hex.DecodeString(literal)
	return b
}

func committedWire() []byte {
	literal := "5353415300010000" + strings.Repeat("01", 16) + "0000000000000001" +
		strings.Repeat("03", 16) + strings.Repeat("04", 32) + strings.Repeat("05", 16) + "0000000000000002" +
		strings.Repeat("06", 32) + strings.Repeat("00", 56)
	b, _ := hex.DecodeString(literal)
	return b
}

func reject(t *testing.T, b []byte, expected [16]byte) {
	t.Helper()
	s, err := appstoreanchorstate.Parse(b, expected)
	if !errors.Is(err, appstoreanchorstate.ErrInvalid) || s != (appstoreanchorstate.State{}) {
		t.Fatalf("invalid state exposed metadata: %v", err)
	}
}

func TestIndependentWireAndHashes(t *testing.T) {
	for _, b := range [][]byte{genesisWire(), committedWire()} {
		if len(b) != 192 {
			t.Fatal("literal fixture length")
		}
		s, err := appstoreanchorstate.Parse(b, store(1))
		if err != nil || !s.Valid() || s.StoreID() != store(1) {
			t.Fatalf("literal state: %v", err)
		}
		raw := s.Bytes()
		want := sha256.Sum256(append([]byte("SSAPP-ANCHOR-STATE-v1"), b...))
		wrong := sha256.Sum256(append([]byte("SSAPP-ANCHOR-STATE-v1\x00"), b...))
		if !bytes.Equal(raw[:], b) || s.Hash() != want || s.Hash() == wrong {
			t.Fatal("exact state bytes/domain hash")
		}
	}
	g, err := appstoreanchorstate.Genesis(store(1))
	if err != nil {
		t.Fatal(err)
	}
	gb := g.Bytes()
	if !bytes.Equal(gb[:], genesisWire()) || g.Sequence() != 0 || g.JournalCount() != 0 || g.CommittedSnapshotID() != ([16]byte{}) || g.CommittedFileHash() != ([32]byte{}) || g.CommittedTransactionID() != ([16]byte{}) {
		t.Fatal("constructor changed canonical genesis")
	}
	b := committedWire()
	s, err := appstoreanchorstate.Parse(b, store(1))
	if err != nil || s.Sequence() != 1 || s.JournalCount() != 2 || s.CommittedSnapshotID() != store(3) || s.CommittedTransactionID() != store(5) || s.CommittedFileHash() != [32]byte(bytes.Repeat([]byte{4}, 32)) || s.JournalHead() != [32]byte(bytes.Repeat([]byte{6}, 32)) {
		t.Fatalf("independent committed fields: %v", err)
	}
	before, digest := s.Bytes(), s.Hash()
	clear(b)
	before[0] = 0
	digest[0] ^= 1
	id := s.CommittedSnapshotID()
	id[0] = 0
	if s.Bytes()[0] != 'S' || s.CommittedSnapshotID() != store(3) || s.Hash() == digest {
		t.Fatal("state aliases caller/accessor bytes")
	}
	if (appstoreanchorstate.State{}).Valid() {
		t.Fatal("zero state admitted")
	}
}

func TestFramingScopeAndCounterRejections(t *testing.T) {
	for _, b := range [][]byte{nil, committedWire()[:191], append(committedWire(), 0)} {
		reject(t, b, store(1))
	}
	for i := 0; i < 4; i++ {
		b := committedWire()
		b[i] ^= 0xff
		reject(t, b, store(1))
	}
	for _, version := range []uint16{0, 2, 256, 65535} {
		b := committedWire()
		binary.BigEndian.PutUint16(b[4:6], version)
		reject(t, b, store(1))
	}
	for _, offset := range append([]int{6, 7}, sequence(136, 192)...) {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			b := committedWire()
			b[offset] = 1
			reject(t, b, store(1))
		})
	}
	reject(t, committedWire(), [16]byte{})
	reject(t, committedWire(), store(2))
	b := committedWire()
	clear(b[8:24])
	reject(t, b, store(1))
	for _, pair := range [][2]uint64{{1, 0}, {3, 2}, {0, 1048577}, {0, ^uint64(0)}, {^uint64(0), 2}} {
		b := committedWire()
		binary.BigEndian.PutUint64(b[24:32], pair[0])
		binary.BigEndian.PutUint64(b[96:104], pair[1])
		if pair[0] == 0 {
			clear(b[32:96])
		}
		reject(t, b, store(1))
	}
	b = committedWire()
	clear(b[104:136])
	reject(t, b, store(1))
	b = genesisWire()
	b[104] ^= 1
	reject(t, b, store(1))
	b = genesisWire()
	copy(b[8:24], bytes.Repeat([]byte{2}, 16))
	reject(t, b, store(2))
	g, err := appstoreanchorstate.Genesis([16]byte{})
	if !errors.Is(err, appstoreanchorstate.ErrInvalid) || g != (appstoreanchorstate.State{}) {
		t.Fatal("zero store genesis")
	}
}

func sequence(from, to int) []int {
	out := make([]int, 0, to-from)
	for i := from; i < to; i++ {
		out = append(out, i)
	}
	return out
}

func TestCommittedTupleAllOrNone(t *testing.T) {
	for _, seq := range []uint64{0, 1} {
		for mask := 0; mask < 8; mask++ {
			b := committedWire()
			binary.BigEndian.PutUint64(b[24:32], seq)
			for i, span := range [][2]int{{32, 48}, {48, 80}, {80, 96}} {
				if mask&(1<<i) == 0 {
					clear(b[span[0]:span[1]])
				}
			}
			if (seq == 0 && mask == 0) || (seq == 1 && mask == 7) {
				if _, err := appstoreanchorstate.Parse(b, store(1)); err != nil {
					t.Fatalf("valid tuple %d/%d: %v", seq, mask, err)
				}
			} else {
				reject(t, b, store(1))
			}
		}
	}
}

func TestReservationBoundariesAreNotHistoryProof(t *testing.T) {
	for _, pair := range [][2]uint64{{0, 1}, {0, 1048576}, {1, 1048576}, {1048576, 1048576}} {
		b := committedWire()
		binary.BigEndian.PutUint64(b[24:32], pair[0])
		binary.BigEndian.PutUint64(b[96:104], pair[1])
		if pair[0] == 0 {
			clear(b[32:96])
		}
		s, err := appstoreanchorstate.Parse(b, store(1))
		if err != nil || s.Sequence() != pair[0] || s.JournalCount() != pair[1] {
			t.Fatalf("counter boundary: %v", err)
		}
	}
	// A positive reservation count cannot retain the empty journal's head.
	b := genesisWire()
	binary.BigEndian.PutUint64(b[96:104], 1)
	reject(t, b, store(1))
}
