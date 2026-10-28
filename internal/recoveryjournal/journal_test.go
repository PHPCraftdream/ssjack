//go:build linux

package recoveryjournal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
)

func TestBindingValidationAndPersistedRoundTrip(t *testing.T) {
	b := validBinding("check-inv", "check-res", "check-tx")
	if !recovery.ValidBinding(b) {
		t.Fatal("valid binding rejected")
	}
	invalid := b
	invalid.Next.Generation = 3
	if recovery.ValidBinding(invalid) {
		t.Fatal("invalid binding accepted")
	}
	j, err := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	intent := recovery.Intent{Binding: b, Phase: recovery.Prepared}
	if err = j.PutIntent(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	got, err := j.LoadIntent(context.Background(), b.Invocation)
	if err != nil || got != intent {
		t.Fatalf("round trip: %v %v", got, err)
	}
	doc := document{Version: 1, Records: []record{{Intent: recovery.Intent{Binding: invalid, Phase: recovery.Prepared}}}}
	doc.Digest = digest(doc)
	j.last = doc
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(j.path(), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = j.LoadIntent(context.Background(), b.Invocation); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid persisted binding: %v", err)
	}
}

func TestDiskRoundTripAndConditionalPhase(t *testing.T) {
	j, e := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	b := validBinding("inv", "res", "tx")
	i := recovery.Intent{Binding: b, Phase: recovery.Prepared}
	if e = j.PutIntent(context.Background(), i); e != nil {
		t.Fatal(e)
	}
	if got, e := j.LoadIntent(context.Background(), "inv"); e != nil || got != i {
		t.Fatalf("%v %v", got, e)
	}
	if e = j.SetPhase(context.Background(), "inv", recovery.Committed); e != nil {
		t.Fatal(e)
	}
	if e = j.SetPhase(context.Background(), "inv", recovery.Committed); e != nil {
		t.Fatalf("idempotent commit: %v", e)
	}
	committed, e := j.LoadIntent(context.Background(), "inv")
	if e != nil || committed.Phase != recovery.Committed || committed.Binding != b {
		t.Fatalf("evidence: %+v %v", committed, e)
	}
	if e = j.SetPhase(context.Background(), "inv", recovery.Prepared); !errors.Is(e, recovery.ErrConflict) {
		t.Fatalf("rollback: %v", e)
	}
}
func TestRefusesReopenAndPersistsQuarantine(t *testing.T) {
	root := filepath.Join(t.TempDir(), "j")
	j, e := Initialize(root, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	b := validBinding("i", "r", "t")
	if e = j.Quarantine(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	if _, e = Initialize(root, time.Second); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e = j.LoadIntent(context.Background(), "i"); !errors.Is(e, recovery.ErrQuarantined) {
		t.Fatal(e)
	}
}
func TestRepeatedIdenticalQuarantine(t *testing.T) {
	j, e := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	b := validBinding("repeat", "repeat-res", "tx")
	for n := 0; n < 2; n++ {
		if e = j.Quarantine(context.Background(), b); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = j.LoadIntent(context.Background(), b.Invocation); !errors.Is(e, recovery.ErrQuarantined) {
		t.Fatal(e)
	}
}

func TestQuarantineConflictFencesAbsentRequestedBinding(t *testing.T) {
	j, e := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	a := validBinding("conflict", "original", "tx")
	b := validBinding("conflict", "other", "tx")
	if e = j.PutIntent(context.Background(), recovery.Intent{Binding: a, Phase: recovery.Prepared}); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 2; n++ {
		if e = j.QuarantineConflict(context.Background(), a, b); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = j.LoadIntent(context.Background(), a.Invocation); !errors.Is(e, recovery.ErrQuarantined) {
		t.Fatal(e)
	}
	if e = j.PutIntent(context.Background(), recovery.Intent{Binding: b, Phase: recovery.Prepared}); !errors.Is(e, recovery.ErrQuarantined) {
		t.Fatal(e)
	}
}

func TestQuarantineConflictPreservesAndFencesBothStoredBindings(t *testing.T) {
	j, e := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	a, b := validBinding("both-a", "both-res-a", "tx-a"), validBinding("both-b", "both-res-b", "tx-b")
	for _, x := range []recovery.Binding{a, b} {
		if e = j.PutIntent(context.Background(), recovery.Intent{Binding: x, Phase: recovery.Prepared}); e != nil {
			t.Fatal(e)
		}
	}
	if e = j.QuarantineConflict(context.Background(), a, b); e != nil {
		t.Fatal(e)
	}
	for _, x := range []recovery.Binding{a, b} {
		got, err := j.LoadIntent(context.Background(), x.Invocation)
		if !errors.Is(err, recovery.ErrQuarantined) {
			t.Fatalf("%+v %v", got, err)
		}
		stored, err := j.load()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, record := range stored.Records {
			if record.Intent.Binding == x && record.Intent.Phase == recovery.Quarantined {
				found = true
			}
		}
		if !found {
			t.Fatalf("quarantined evidence missing for %s", x.Invocation)
		}
		if e = j.PutIntent(context.Background(), prepared("new-"+x.Invocation, x.Resource)); !errors.Is(e, recovery.ErrQuarantined) {
			t.Fatal(e)
		}
	}
}
func TestDiskConflictsAndQuarantineBlocksBothBindings(t *testing.T) {
	j, e := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	a := prepared("one", "res-one")
	if e = j.PutIntent(context.Background(), a); e != nil {
		t.Fatal(e)
	}
	if e = j.PutIntent(context.Background(), prepared("one", "other")); !errors.Is(e, recovery.ErrConflict) {
		t.Fatal(e)
	}
	if e = j.PutIntent(context.Background(), prepared("other", "res-one")); !errors.Is(e, recovery.ErrConflict) {
		t.Fatal(e)
	}
	b := validBinding("two", "res-two", "tx-two")
	if e = j.QuarantineConflict(context.Background(), a.Binding, b); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"one", "two"} {
		if _, e = j.LoadIntent(context.Background(), id); !errors.Is(e, recovery.ErrQuarantined) {
			t.Fatalf("%s: %v", id, e)
		}
	}
	if e = j.PutIntent(context.Background(), prepared("three", "res-two")); !errors.Is(e, recovery.ErrQuarantined) {
		t.Fatal(e)
	}
	if e = j.PutIntent(context.Background(), prepared("two", "res-three")); !errors.Is(e, recovery.ErrQuarantined) {
		t.Fatal(e)
	}
}

func TestBindingValidationBoundaryMatrix(t *testing.T) {
	base := validBinding("matrix-inv", "matrix-res", "matrix-tx")
	valid := base
	valid.Stage = recovery.InvocationStage
	valid.Expected = recovery.State{Resource: valid.Resource, Generation: 4, Hash: valid.RequestHash, Transaction: "prior-tx"}
	valid.Next.Generation = 5
	valid.Next.Transaction = valid.Transaction
	invalid := []struct {
		name string
		edit func(*recovery.Binding)
	}{{"stage", func(b *recovery.Binding) { b.Stage = 255 }}, {"ascii", func(b *recovery.Binding) { b.Invocation = "bad\nvalue" }}, {"utf8", func(b *recovery.Binding) {
		b.Resource = "rés"
		b.Expected.Resource = b.Resource
		b.Next.Resource = b.Resource
	}}, {"invocation", func(b *recovery.Binding) { b.Invocation = "" }}, {"resource", func(b *recovery.Binding) { b.Next.Resource = "other" }}, {"transaction", func(b *recovery.Binding) { b.Next.Transaction = "other" }}, {"genesis", func(b *recovery.Binding) { b.Expected.Generation = 0; b.Expected.Transaction = "prior-tx" }}, {"hash", func(b *recovery.Binding) { b.Next.Hash = b.Expected.Hash }}, {"overflow", func(b *recovery.Binding) { b.Expected.Generation = ^uint64(0); b.Next.Generation = 0 }}}
	if !recovery.ValidBinding(base) || !recovery.ValidBinding(valid) {
		t.Fatal("valid binding rejected")
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			b := base
			tc.edit(&b)
			if recovery.ValidBinding(b) {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}
func TestDirectValidDocValidationBoundaryMatrix(t *testing.T) {
	b := validBinding("doc-inv", "doc-res", "doc-tx")
	baseline := document{Version: 1, Records: []record{{Intent: recovery.Intent{Binding: b, Phase: recovery.Prepared}}}}
	if !validDoc(baseline) {
		t.Fatal("valid document rejected")
	}
	invalid := []struct {
		name string
		doc  document
	}{{"version", document{Version: 2, Records: baseline.Records}}, {"phase", document{Version: 1, Records: []record{{Intent: recovery.Intent{Binding: b, Phase: recovery.Phase(0)}}}}}, {"oversized", document{Version: 1, Records: make([]record, maxEntries+1)}}}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if validDoc(tc.doc) {
				t.Fatal("invalid document accepted")
			}
		})
	}
}
func TestDirectValidDocRejectsDuplicateBindings(t *testing.T) {
	b := validBinding("dup", "dup-res", "tx")
	i := recovery.Intent{Binding: b, Phase: recovery.Prepared}
	if validDoc(document{Version: 1, Records: []record{{Intent: i}, {Intent: i}}}) {
		t.Fatal("duplicates accepted")
	}
}
func TestMalformedAndOversizedDiskDenied(t *testing.T) {
	for _, name := range []string{"duplicate-json-key"} {
		t.Run(name, func(t *testing.T) {
			j, e := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			base := document{Version: 1, Records: []record{{Intent: recovery.Intent{Binding: validBinding("base", "base-res", "tx"), Phase: recovery.Prepared}}}}
			base.Digest = digest(base)
			j.last = base
			b, e := json.Marshal(base)
			if e != nil {
				t.Fatal(e)
			}
			b = []byte(strings.Replace(string(b), `"version":1`, `"version":1,"version":1`, 1))
			if e = os.WriteFile(j.path(), b, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e = j.LoadIntent(context.Background(), "x"); !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
			if string(mustJSON(j.last)) != string(mustJSON(base)) {
				t.Fatal("invalid disk document replaced cached last")
			}
		})
	}
}
func TestSyncDirectoryCloseError(t *testing.T) {
	root := t.TempDir()
	closed := false
	closeErr := errors.New("close")
	err := syncDirectory(root, os.Open, func(f *os.File) error { return f.Sync() }, func(f *os.File) error { closed = true; _ = f.Close(); return closeErr })
	if !closed || !errors.Is(err, closeErr) {
		t.Fatalf("close error not propagated: closed=%v err=%v", closed, err)
	}
}
