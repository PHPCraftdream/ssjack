package appstoreanchorrequest_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func reject(t *testing.T, request appstoreanchorrequest.Request, err error) {
	t.Helper()
	if !errors.Is(err, appstoreanchorrequest.ErrInvalid) || request != (appstoreanchorrequest.Request{}) {
		t.Fatalf("invalid plan exposed metadata: %v", err)
	}
}

func previous(t *testing.T, sequence, count uint64) appstoreanchorstate.State {
	t.Helper()
	b := genesisWire()
	binary.BigEndian.PutUint64(b[24:32], sequence)
	binary.BigEndian.PutUint64(b[96:104], count)
	if sequence != 0 {
		copy(b[32:48], bytes.Repeat([]byte{8}, 16))
		copy(b[48:80], bytes.Repeat([]byte{9}, 32))
		copy(b[80:96], bytes.Repeat([]byte{10}, 16))
	}
	if count != 0 {
		copy(b[104:136], bytes.Repeat([]byte{11}, 32))
	}
	return state(t, b)
}

func TestInvalidAndCrossKindPlans(t *testing.T) {
	read, _ := appstoreanchorrequest.NewRead(id(1), id(2))
	create, _ := appstoreanchorrequest.NewCreate(id(1))
	reservation, err := appstoreanchorrequest.PlanReservation(state(t, genesisWire()), entry(t, 0, 3, 4))
	if err != nil {
		t.Fatal(err)
	}
	commit, err := appstoreanchorrequest.PlanCommit(reservation, hash(7))
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []appstoreanchorrequest.Request{{}, read, create, commit} {
		r, err := appstoreanchorrequest.PlanCommit(wrong, hash(7))
		reject(t, r, err)
	}
	r, err := appstoreanchorrequest.PlanCommit(reservation, [32]byte{})
	reject(t, r, err)
	r, err = appstoreanchorrequest.NewRead([16]byte{}, id(2))
	reject(t, r, err)
	r, err = appstoreanchorrequest.NewRead(id(1), [16]byte{})
	reject(t, r, err)
	r, err = appstoreanchorrequest.NewCreate([16]byte{})
	reject(t, r, err)
	r, err = appstoreanchorrequest.PlanReservation(appstoreanchorstate.State{}, entry(t, 0, 3, 4))
	reject(t, r, err)
	r, err = appstoreanchorrequest.PlanReservation(state(t, genesisWire()), appstorejournal.Entry{})
	reject(t, r, err)
	r, err = appstoreanchorrequest.PlanReservation(previous(t, 0, 1), entry(t, 0, 3, 4))
	reject(t, r, err)
	if (appstoreanchorrequest.Request{}).Valid() || (appstoreanchorrequest.Request{}).Bytes() != nil {
		t.Fatal("zero request claims a plan")
	}
}

func TestKnownReuseAndPreservedTransitionFields(t *testing.T) {
	old := previous(t, 1, 1)
	for _, e := range []appstorejournal.Entry{entry(t, 1, 8, 12), entry(t, 1, 12, 10)} {
		r, err := appstoreanchorrequest.PlanReservation(old, e)
		reject(t, r, err)
	}
	reservation, err := appstoreanchorrequest.PlanReservation(old, entry(t, 1, 12, 13))
	if err != nil {
		t.Fatal(err)
	}
	reserved, ok := reservation.ProposedState()
	if !ok || reserved.Sequence() != old.Sequence() || reserved.JournalCount() != 2 || reserved.CommittedSnapshotID() != old.CommittedSnapshotID() || reserved.CommittedFileHash() != old.CommittedFileHash() || reserved.CommittedTransactionID() != old.CommittedTransactionID() {
		t.Fatal("reservation altered committed tuple")
	}
	commit, err := appstoreanchorrequest.PlanCommit(reservation, hash(14))
	if err != nil {
		t.Fatal(err)
	}
	next, ok := commit.ProposedState()
	if !ok || next.Sequence() != 2 || next.JournalCount() != reserved.JournalCount() || next.JournalHead() != reserved.JournalHead() || next.CommittedSnapshotID() != id(12) || next.CommittedTransactionID() != id(13) || next.CommittedFileHash() != hash(14) {
		t.Fatal("commit changed reservation identity/count/head")
	}
}

func TestLastReservationBoundary(t *testing.T) {
	old := previous(t, 1048575, 1048575)
	reservation, err := appstoreanchorrequest.PlanReservation(old, entry(t, 1048575, 12, 13))
	if err != nil {
		t.Fatal(err)
	}
	commit, err := appstoreanchorrequest.PlanCommit(reservation, hash(14))
	if err != nil {
		t.Fatal(err)
	}
	next, _ := commit.ProposedState()
	if next.Sequence() != 1048576 || next.JournalCount() != 1048576 {
		t.Fatal("last valid reservation was not preserved")
	}
	r, err := appstoreanchorrequest.PlanReservation(next, entry(t, 1048575, 15, 16))
	reject(t, r, err)
}

func TestKeysDoNotReplaceDurableCanonicalBinding(t *testing.T) {
	// The protocol key commits the entry, not every predecessor field. A service
	// must reject equal keys/IDs used with different canonical mutation bytes.
	e := entry(t, 1, 12, 13)
	a, err := appstoreanchorrequest.PlanReservation(previous(t, 0, 1), e)
	if err != nil {
		t.Fatal(err)
	}
	b, err := appstoreanchorrequest.PlanReservation(previous(t, 1, 1), e)
	if err != nil {
		t.Fatal(err)
	}
	ka, _ := a.IdempotencyKey()
	kb, _ := b.IdempotencyKey()
	if ka != kb || a.RequestID() != b.RequestID() || bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("canonical-binding collision witness changed")
	}
}
