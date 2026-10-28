//go:build linux

package recoveryintegration

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
	"github.com/PHPCraftdream/ssjack/internal/recoveryjournal"
)

func validBinding(i, r, tx string) recovery.Binding {
	return recovery.Binding{Stage: recovery.Reservation, Invocation: i, Resource: r, Transaction: tx, Expected: recovery.State{Resource: r}, Next: recovery.State{Resource: r, Generation: 1, Transaction: tx, Hash: recovery.Hash{1}}}
}

func prepared(i, r string) recovery.Intent {
	return recovery.Intent{Binding: validBinding(i, r, "tx"), Phase: recovery.Prepared}
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

func TestCapacityAndIdempotence(t *testing.T) {
	j, e := recoveryjournal.Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 7; n++ {
		i := recovery.Intent{Binding: validBinding(fmt.Sprintf("i%d", n), fmt.Sprintf("r%d", n), fmt.Sprintf("t%d", n)), Phase: recovery.Prepared}
		if e = j.PutIntent(context.Background(), i); e != nil {
			t.Fatal(e)
		}
	}
	i := recovery.Intent{Binding: validBinding("i0", "r0", "t0"), Phase: recovery.Prepared}
	if e = j.PutIntent(context.Background(), i); e != nil {
		t.Fatal(e)
	}
	if e = j.PutIntent(context.Background(), recovery.Intent{Binding: validBinding("overflow", "overflow-res", "overflow-tx"), Phase: recovery.Prepared}); !errors.Is(e, recoveryjournal.ErrUnavailable) {
		t.Fatal(e)
	}
}

func TestDiskRoundTripAndConditionalPhase(t *testing.T) {
	j, e := recoveryjournal.Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
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
	j, e := recoveryjournal.Initialize(root, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	b := validBinding("i", "r", "t")
	if e = j.Quarantine(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	if _, e = recoveryjournal.Initialize(root, time.Second); !errors.Is(e, recoveryjournal.ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e = j.LoadIntent(context.Background(), "i"); !errors.Is(e, recovery.ErrQuarantined) {
		t.Fatal(e)
	}
}
func TestRepeatedIdenticalQuarantine(t *testing.T) {
	j, e := recoveryjournal.Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
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
	j, e := recoveryjournal.Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
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

func TestDiskConflictsAndQuarantineBlocksBothBindings(t *testing.T) {
	j, e := recoveryjournal.Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
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
