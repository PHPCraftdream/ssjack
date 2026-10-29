package appstorejournal_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func candidate(t *testing.T, index uint64, snapshot, transaction byte) appstorejournal.Entry {
	t.Helper()
	e, err := appstorejournal.NewEntry(index, id(snapshot), id(transaction))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func rejectFresh(t *testing.T, s appstoreanchorstate.State, r io.Reader, e appstorejournal.Entry, want error) {
	t.Helper()
	p, err := appstorejournal.CheckFreshPair(s, r, e)
	if !errors.Is(err, want) || p != (appstorejournal.Prefix{}) {
		t.Fatalf("freshness failure leaked metadata: %v", err)
	}
}

func TestFreshPairExactPrefixAndGenesis(t *testing.T) {
	s, b, head := chain(t)
	e := candidate(t, 2, 7, 8)
	suffix := wireEntry(2, 7, 8)
	r := bytes.NewReader(append(append([]byte(nil), b...), suffix...))
	p, err := appstorejournal.CheckFreshPair(s, r, e)
	if err != nil || !p.Valid() || p.StoreID() != id(1) || p.StateHash() != s.Hash() || p.Head() != head || p.Count() != 2 || p.ConsumedBytes() != 80 || r.Len() != len(suffix) {
		t.Fatalf("prefix/suffix mismatch: %v", err)
	}
	remaining, _ := io.ReadAll(r)
	if !bytes.Equal(remaining, suffix) {
		t.Fatal("untrusted suffix changed")
	}
	g, err := appstoreanchorstate.Genesis(id(1))
	if err != nil {
		t.Fatal(err)
	}
	counted := &countedReader{r: bytes.NewReader(suffix)}
	p, err = appstorejournal.CheckFreshPair(g, counted, candidate(t, 0, 7, 8))
	if err != nil || !p.Valid() || p.Count() != 0 || counted.calls != 0 {
		t.Fatalf("genesis touched reader: %v", err)
	}
}

func TestFreshPairRejectsEveryHistoricalID(t *testing.T) {
	s, b, _ := chain(t)
	for _, pair := range [][2]byte{{3, 8}, {5, 8}, {7, 4}, {7, 6}, {4, 8}, {6, 8}, {7, 3}, {7, 5}, {3, 4}, {5, 6}} {
		counted := &countedReader{r: bytes.NewReader(b), limit: 3}
		rejectFresh(t, s, counted, candidate(t, 2, pair[0], pair[1]), appstorejournal.ErrReused)
		if counted.received != 80 || counted.largest > 40 {
			t.Fatal("collision published before checking entire bounded prefix")
		}
	}
	// Prefix integrity takes precedence over an early apparent collision.
	corrupted := append([]byte(nil), b...)
	corrupted[48] ^= 1
	rejectFresh(t, s, bytes.NewReader(corrupted), candidate(t, 2, 3, 8), appstorejournal.ErrInvalid)
	rejectFresh(t, s, bytes.NewReader(b[:79]), candidate(t, 2, 3, 8), appstorejournal.ErrInvalid)
	rejectFresh(t, s, io.MultiReader(bytes.NewReader(b[:40]), &fullError{data: b[40:]}), candidate(t, 2, 3, 8), appstorejournal.ErrUnavailable)
	wrong := s.JournalHead()
	wrong[0] ^= 1
	rejectFresh(t, state(t, id(1), 2, wrong), bytes.NewReader(b), candidate(t, 2, 3, 8), appstorejournal.ErrInvalid)
	// Existing inspection remains commitment-only, including repeated historical IDs.
	repeated := append(wireEntry(0, 3, 4), wireEntry(1, 3, 4)...)
	head := independentStep(id(1), initialHead(id(1)), repeated[:40])
	head = independentStep(id(1), head, repeated[40:])
	same := state(t, id(1), 2, head)
	if _, err := appstorejournal.InspectPrefix(same, bytes.NewReader(repeated)); err != nil {
		t.Fatal(err)
	}
	if _, err := appstorejournal.CheckFreshPair(same, bytes.NewReader(repeated), candidate(t, 2, 7, 8)); err != nil {
		t.Fatal("unrelated old duplicates changed candidate check", err)
	}
}

func TestFreshPairInvalidInputsAndReadFailures(t *testing.T) {
	s, b, _ := chain(t)
	e := candidate(t, 2, 7, 8)
	for _, row := range []struct {
		s appstoreanchorstate.State
		e appstorejournal.Entry
	}{
		{appstoreanchorstate.State{}, e},
		{s, appstorejournal.Entry{}},
		{s, candidate(t, 0, 7, 8)},
		{s, candidate(t, 1, 7, 8)},
		{s, candidate(t, 3, 7, 8)},
		{state(t, id(1), 1<<20, [32]byte(bytes.Repeat([]byte{9}, 32))), candidate(t, (1<<20)-1, 7, 8)},
	} {
		counted := &countedReader{r: bytes.NewReader(b)}
		rejectFresh(t, row.s, counted, row.e, appstorejournal.ErrInvalid)
		if counted.calls != 0 {
			t.Fatal("invalid candidate read input")
		}
	}
	for _, end := range []int{0, 1, 39, 40, 79} {
		rejectFresh(t, s, bytes.NewReader(b[:end]), e, appstorejournal.ErrInvalid)
	}
	rejectFresh(t, s, nil, e, appstorejournal.ErrUnavailable)
	n := &noProgress{}
	rejectFresh(t, s, n, e, appstorejournal.ErrUnavailable)
	if n.calls != 1 {
		t.Fatal("no-progress retry")
	}
	rejectFresh(t, s, &fullError{data: b[:40]}, e, appstorejournal.ErrUnavailable)
	rejectFresh(t, state(t, id(2), 2, s.JournalHead()), bytes.NewReader(b), e, appstorejournal.ErrInvalid)
	short := &countedReader{r: bytes.NewReader(b), limit: 1}
	if _, err := appstorejournal.CheckFreshPair(s, short, e); err != nil || short.received != 80 || short.largest > 40 {
		t.Fatalf("short reads: %v", err)
	}
}
