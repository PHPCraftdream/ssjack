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

func intentFixture(t *testing.T) (appstoreanchorrequest.Request, []byte) {
	t.Helper()
	store := id(1)
	g := genesisWire()
	e := entry(t, 0, 3, 4)
	reservation, err := appstoreanchorrequest.PlanReservation(state(t, g), e)
	if err != nil {
		t.Fatal(err)
	}
	candidate := hash(7)
	commit, err := appstoreanchorrequest.PlanCommit(reservation, candidate)
	if err != nil {
		t.Fatal(err)
	}
	eraw := binary.BigEndian.AppendUint64(nil, 0)
	eraw = append(eraw, bytes.Repeat([]byte{3}, 16)...)
	eraw = append(eraw, bytes.Repeat([]byte{4}, 16)...)
	reserved := append([]byte(nil), g...)
	head := sum("SSAPP-JOURNAL-ENTRY-v1", store[:], g[104:136], eraw)
	binary.BigEndian.PutUint64(reserved[96:104], 1)
	copy(reserved[104:136], head[:])
	expected := sum("SSAPP-ANCHOR-STATE-v1", reserved)
	next := append([]byte(nil), reserved...)
	binary.BigEndian.PutUint64(next[24:32], 1)
	copy(next[32:48], bytes.Repeat([]byte{3}, 16))
	copy(next[48:80], candidate[:])
	transaction := id(4)
	copy(next[80:96], transaction[:])
	key := sum("SSAPP-COMMIT-v1", store[:], transaction[:], candidate[:])
	want := append([]byte("SSAPCMT1"), transaction[:]...)
	want = append(want, expected[:]...)
	want = append(want, next...)
	want = append(want, key[:]...)
	return commit, append(want, candidate[:]...)
}

func TestIntentIndependentBytesAndExactCASReconstruction(t *testing.T) {
	commit, want := intentFixture(t)
	intent, err := appstoreanchorrequest.NewIntent(commit)
	if err != nil || !intent.Valid() || len(want) != 312 {
		t.Fatalf("intent construction: %v", err)
	}
	b := intent.Bytes()
	if !bytes.Equal(b[:], want) {
		t.Fatal("independent intent wire mismatch")
	}
	parsed, err := appstoreanchorrequest.ParseIntent(want, id(1))
	if err != nil || parsed != intent {
		t.Fatalf("intent parse: %v", err)
	}
	replayed, ok := parsed.Request()
	if !ok || replayed != commit || !bytes.Equal(replayed.Bytes(), commit.Bytes()) || replayed.RequestID() != commit.RequestID() {
		t.Fatal("intent synthesized a different CAS")
	}
	clear(want)
	b[0] = 0
	if intent.Bytes()[0] != 'S' || parsed.Bytes()[0] != 'S' {
		t.Fatal("intent aliases input or accessor")
	}
	var zero appstoreanchorrequest.Intent
	r, ok := zero.Request()
	if zero.Valid() || ok || r.Valid() {
		t.Fatal("zero intent grants a request")
	}
}

func TestIntentMalformedFieldsAndScope(t *testing.T) {
	_, original := intentFixture(t)
	for _, raw := range [][]byte{nil, original[:311], append(append([]byte(nil), original...), 0)} {
		i, err := appstoreanchorrequest.ParseIntent(raw, id(1))
		if !errors.Is(err, appstoreanchorrequest.ErrInvalid) || i != (appstoreanchorrequest.Intent{}) {
			t.Fatal("invalid length exposed intent")
		}
	}
	for _, scope := range [][16]byte{{}, id(2)} {
		i, err := appstoreanchorrequest.ParseIntent(original, scope)
		if !errors.Is(err, appstoreanchorrequest.ErrInvalid) || i != (appstoreanchorrequest.Intent{}) {
			t.Fatal("wrong intent scope")
		}
	}
	for name, mutate := range map[string]func([]byte){
		"magic":             func(b []byte) { b[0] = 'X' },
		"transaction":       func(b []byte) { b[8] ^= 1 },
		"zero-transaction":  func(b []byte) { clear(b[8:24]) },
		"zero-expected":     func(b []byte) { clear(b[24:56]) },
		"same-state":        func(b []byte) { h := sum("SSAPP-ANCHOR-STATE-v1", b[56:248]); copy(b[24:56], h[:]) },
		"state-magic":       func(b []byte) { b[56] = 'X' },
		"state-reserved":    func(b []byte) { b[56+136] = 1 },
		"key":               func(b []byte) { b[248] ^= 1 },
		"candidate":         func(b []byte) { b[280] ^= 1 },
		"zero-candidate":    func(b []byte) { clear(b[280:312]) },
		"state-file":        func(b []byte) { b[56+48] ^= 1 },
		"state-transaction": func(b []byte) { b[56+80] ^= 1 },
		"genesis":           func(b []byte) { copy(b[56:248], genesisWire()) },
	} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte(nil), original...)
			mutate(b)
			i, err := appstoreanchorrequest.ParseIntent(b, id(1))
			if !errors.Is(err, appstoreanchorrequest.ErrInvalid) || i != (appstoreanchorrequest.Intent{}) {
				t.Fatalf("malformed intent exposed data: %v", err)
			}
		})
	}
}

func TestIntentRejectsOtherRequestKinds(t *testing.T) {
	read, _ := appstoreanchorrequest.NewRead(id(1), id(2))
	create, _ := appstoreanchorrequest.NewCreate(id(1))
	reserve, err := appstoreanchorrequest.PlanReservation(state(t, genesisWire()), entry(t, 0, 3, 4))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []appstoreanchorrequest.Request{{}, read, create, reserve} {
		i, err := appstoreanchorrequest.NewIntent(r)
		if !errors.Is(err, appstoreanchorrequest.ErrInvalid) || i != (appstoreanchorrequest.Intent{}) {
			t.Fatal("non-commit intent admitted")
		}
	}
}
