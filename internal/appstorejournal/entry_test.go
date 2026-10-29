package appstorejournal_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func id(value byte) [16]byte { return [16]byte(bytes.Repeat([]byte{value}, 16)) }

func wireEntry(index uint64, snapshot, transaction byte) []byte {
	b := binary.BigEndian.AppendUint64(nil, index)
	b = append(b, bytes.Repeat([]byte{snapshot}, 16)...)
	return append(b, bytes.Repeat([]byte{transaction}, 16)...)
}

func initialHead(store [16]byte) [32]byte {
	return sha256.Sum256(append([]byte("SSAPP-JOURNAL-GENESIS-v1"), store[:]...))
}

func independentStep(store [16]byte, previous [32]byte, entry []byte) [32]byte {
	message := append([]byte("SSAPP-JOURNAL-ENTRY-v1"), store[:]...)
	message = append(message, previous[:]...)
	return sha256.Sum256(append(message, entry...))
}

func state(t *testing.T, store [16]byte, count uint64, head [32]byte) appstoreanchorstate.State {
	t.Helper()
	b := make([]byte, 192)
	copy(b[:4], "SSAS")
	binary.BigEndian.PutUint16(b[4:6], 1)
	copy(b[8:24], store[:])
	binary.BigEndian.PutUint64(b[96:104], count)
	copy(b[104:136], head[:])
	s, err := appstoreanchorstate.Parse(b, store)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func chain(t *testing.T) (appstoreanchorstate.State, []byte, [32]byte) {
	t.Helper()
	first, second := wireEntry(0, 3, 4), wireEntry(1, 5, 6)
	head := independentStep(id(1), initialHead(id(1)), first)
	head = independentStep(id(1), head, second)
	return state(t, id(1), 2, head), append(first, second...), head
}

func TestIndependentEntryAndHashStep(t *testing.T) {
	b, err := hex.DecodeString("0000000000000000" + strings.Repeat("03", 16) + strings.Repeat("04", 16))
	if err != nil || len(b) != 40 {
		t.Fatal("literal entry fixture")
	}
	e, err := appstorejournal.ParseEntry(b, 0)
	if err != nil || !e.Valid() || e.Index() != 0 || e.SnapshotID() != id(3) || e.TransactionID() != id(4) {
		t.Fatalf("entry vector: %v", err)
	}
	made, err := appstorejournal.NewEntry(0, id(3), id(4))
	if err != nil || made != e {
		t.Fatal("entry constructor bytes differ")
	}
	before := e.Bytes()
	if !bytes.Equal(before[:], b) {
		t.Fatal("entry bytes changed")
	}
	want := independentStep(id(1), initialHead(id(1)), b)
	got, err := appstorejournal.NextHead(id(1), initialHead(id(1)), e)
	if err != nil || got != want {
		t.Fatalf("independent chain step: %v", err)
	}
	wrongMessage := append([]byte("SSAPP-JOURNAL-ENTRY-v1\x00"), bytes.Repeat([]byte{1}, 16)...)
	previous := initialHead(id(1))
	wrongMessage = append(wrongMessage, previous[:]...)
	wrong := sha256.Sum256(append(wrongMessage, b...))
	if got == wrong {
		t.Fatal("wrong hash domain matched")
	}
	clear(b)
	before[0] = 1
	returned := e.SnapshotID()
	returned[0] = 0
	if e.Index() != 0 || e.SnapshotID() != id(3) || e.TransactionID() != id(4) {
		t.Fatal("entry aliases caller or arrays")
	}
}

func TestEntryBoundsAndInvalidHashInputs(t *testing.T) {
	for _, index := range []uint64{0, 1048575} {
		e, err := appstorejournal.NewEntry(index, id(1), id(2))
		if err != nil || e.Index() != index {
			t.Fatalf("index boundary: %v", err)
		}
	}
	for _, index := range []uint64{1048576, ^uint64(0)} {
		e, err := appstorejournal.NewEntry(index, id(1), id(2))
		if !errors.Is(err, appstorejournal.ErrInvalid) || e != (appstorejournal.Entry{}) {
			t.Fatal("oversized index admitted")
		}
	}
	for _, b := range [][]byte{nil, make([]byte, 39), append(wireEntry(0, 1, 2), 0), wireEntry(1, 1, 2), wireEntry(0, 0, 2), wireEntry(0, 1, 0)} {
		e, err := appstorejournal.ParseEntry(b, 0)
		if !errors.Is(err, appstorejournal.ErrInvalid) || e != (appstorejournal.Entry{}) {
			t.Fatal("invalid entry exposed data")
		}
	}
	e, _ := appstorejournal.NewEntry(0, id(1), id(2))
	for _, row := range []struct {
		store [16]byte
		head  [32]byte
		entry appstorejournal.Entry
	}{
		{[16]byte{}, initialHead(id(1)), e},
		{id(1), [32]byte{}, e},
		{id(1), initialHead(id(1)), appstorejournal.Entry{}},
	} {
		head, err := appstorejournal.NextHead(row.store, row.head, row.entry)
		if !errors.Is(err, appstorejournal.ErrInvalid) || head != ([32]byte{}) {
			t.Fatal("invalid hash input exposed a result")
		}
	}
}
