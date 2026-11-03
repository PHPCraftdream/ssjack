//go:build linux

package recoveryintegration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
	"github.com/PHPCraftdream/ssjack/internal/recoveryjournal"
)

type markerJournal struct {
	*recoveryjournal.Journal
	marker string
	calls  int
	loads  int
}

func (j *markerJournal) LoadIntent(ctx context.Context, invocation string) (recovery.Intent, error) {
	j.loads++
	return j.Journal.LoadIntent(ctx, invocation)
}

func (j *markerJournal) QuarantineConflict(ctx context.Context, a, b recovery.Binding) error {
	j.calls++
	if err := os.WriteFile(j.marker, []byte("interrupted"), 0600); err != nil {
		return err
	}
	return j.Journal.QuarantineConflict(ctx, a, b)
}

type callerGate struct {
	anchorIO, journalCalls, admits int
	closed                         bool
	bindings                       map[string]recovery.Binding
}

func (g *callerGate) admit(b recovery.Binding) error {
	if g.closed {
		return recovery.ErrUnavailable
	}
	if prior, ok := g.bindings[b.Transaction]; ok && prior != b {
		return recovery.ErrConflict
	}
	g.bindings[b.Transaction] = b
	g.admits++
	return nil
}

func (g *callerGate) recover(ctx context.Context, m recovery.Machine, b recovery.Binding) error {
	if err := g.admit(b); err != nil {
		return err
	}
	err := m.Recover(ctx, b)
	if errors.Is(err, recovery.ErrUnavailable) {
		g.closed = true
	}
	return err
}
func (g *callerGate) reconcile() { g.closed = false }

func TestCallerGateHoldsAfterConflictQuarantineFailure(t *testing.T) {
	j, root, a, original := setup(t)
	if err := j.PutIntent(context.Background(), recovery.Intent{Binding: original, Phase: recovery.Prepared}); err != nil {
		t.Fatal(err)
	}
	requested := original
	requested.Invocation = original.Invocation
	requested.Transaction = "different-tx"
	requested.Next.Transaction = requested.Transaction
	requested.Resource = "different-resource"
	requested.Expected = recovery.State{Resource: requested.Resource, Generation: 4, Hash: original.Expected.Hash, Transaction: "prior-other"}
	requested.Next = recovery.State{Resource: requested.Resource, Generation: 5, Hash: original.Next.Hash, Transaction: requested.Transaction}
	wrapped := &markerJournal{Journal: j, marker: filepath.Join(root, "journal.json.pending")}
	if err := os.Remove(wrapped.marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	gate := &callerGate{bindings: map[string]recovery.Binding{}}
	gate.bindings[original.Transaction] = original
	machine := recovery.Machine{Anchor: a, Journal: wrapped}
	if err := gate.recover(context.Background(), machine, requested); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("Recover=%v", err)
	}
	if !gate.closed {
		t.Fatal("gate did not close after failed conflict quarantine")
	}
	if gate.admits != 1 || wrapped.calls != 1 || gate.journalCalls != 0 || a.reads != 0 || a.swaps != 0 {
		t.Fatalf("calls=%d anchor reads=%d swaps=%d", wrapped.calls, a.reads, a.swaps)
	}
	if _, err := os.Stat(wrapped.marker); err != nil {
		t.Fatalf("pending marker absent: %v", err)
	}
	if _, err := j.LoadIntent(context.Background(), original.Invocation); !errors.Is(err, recoveryjournal.ErrUnavailable) {
		t.Fatalf("LoadIntent with pending marker=%v", err)
	}
	var evidence struct {
		Records []struct {
			Intent  recovery.Intent    `json:"intent"`
			Blocked []recovery.Binding `json:"blocked"`
		} `json:"records"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "journal.json"))
	if err != nil {
		t.Fatalf("read quarantined evidence: %v", err)
	}
	if err = json.Unmarshal(raw, &evidence); err != nil {
		t.Fatalf("decode quarantined evidence: %v", err)
	}
	if len(evidence.Records) != 1 || evidence.Records[0].Intent.Binding != original || evidence.Records[0].Intent.Phase != recovery.Prepared || len(evidence.Records[0].Blocked) != 0 {
		t.Fatalf("conflict evidence=%+v", evidence.Records)
	}
	other := original
	other.Transaction, other.Invocation, other.Resource = "other-tx", "other-invocation", "other-resource"
	other.Expected = recovery.State{Resource: other.Resource, Generation: 4, Hash: original.Expected.Hash, Transaction: "prior-other"}
	other.Next = recovery.State{Resource: other.Resource, Generation: 5, Hash: original.Next.Hash, Transaction: other.Transaction}
	beforeAdmits, beforeJournal, beforeReads := gate.admits, wrapped.calls, a.reads
	beforeLoads := wrapped.loads
	if err := gate.recover(context.Background(), machine, other); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("closed gate admitted unrelated binding: %v", err)
	}
	if !gate.closed || gate.admits != beforeAdmits || wrapped.calls != beforeJournal || wrapped.loads != beforeLoads || a.reads != beforeReads {
		t.Fatalf("closed-gate evidence: closed=%v admits=%d journal=%d reads=%d", gate.closed, gate.admits, wrapped.calls, a.reads)
	}
	gate.reconcile()
	if gate.closed {
		t.Fatal("gate did not open after simulated trusted reconciliation")
	}
	beforeLoads = wrapped.loads
	if err := gate.recover(context.Background(), machine, other); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("journal unexpectedly available after reconciliation: %v", err)
	}
	if !gate.closed || gate.admits != beforeAdmits+1 || wrapped.calls != beforeJournal || wrapped.loads != beforeLoads+1 || a.reads != beforeReads {
		t.Fatalf("post-reconciliation evidence: closed=%v admits=%d journal=%d reads=%d", gate.closed, gate.admits, wrapped.calls, a.reads)
	}
	if _, err := os.Stat(filepath.Join(root, "journal.json.new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected new marker: %v", err)
	}
}
