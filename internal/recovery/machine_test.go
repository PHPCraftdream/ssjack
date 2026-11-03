package recovery

import (
	"context"
	"errors"
	"testing"
)

type jmem struct {
	i                       Intent
	ok                      bool
	phaseErr, quarantineErr error
	quarantined             []Binding
}

func (j *jmem) LoadIntent(_ context.Context, _ string) (Intent, error) {
	if !j.ok {
		return Intent{}, ErrNotFound
	}
	return j.i, nil
}
func (j *jmem) PutIntent(_ context.Context, i Intent) error {
	if j.ok {
		return ErrConflict
	}
	j.i = i
	j.ok = true
	return nil
}
func (j *jmem) SetPhase(_ context.Context, _ string, p Phase) error {
	if j.phaseErr != nil {
		return j.phaseErr
	}
	j.i.Phase = p
	return nil
}
func (j *jmem) Quarantine(_ context.Context, b Binding) error {
	if j.quarantineErr != nil {
		return j.quarantineErr
	}
	j.quarantined = append(j.quarantined, b)
	j.i = Intent{b, Quarantined}
	j.ok = true
	return nil
}

func (j *jmem) QuarantineConflict(_ context.Context, stored, requested Binding) error {
	if j.quarantineErr != nil {
		return j.quarantineErr
	}
	j.quarantined = append(j.quarantined, stored)
	if stored.Resource != requested.Resource {
		j.quarantined = append(j.quarantined, requested)
	}
	j.i, j.ok = Intent{stored, Quarantined}, true
	return nil
}

type amem struct {
	s               State
	casErr, readErr error
	apply           bool
	calls, reads    int
	lastTransaction string
}

func (a *amem) Read(context.Context, string) (State, error) { a.reads++; return a.s, a.readErr }
func (a *amem) CompareAndSwap(_ context.Context, o, n State, transaction string) error {
	a.calls++
	a.lastTransaction = transaction
	if a.s != o {
		return ErrConflict
	}
	if a.casErr == nil || a.apply {
		a.s = n
	}
	return a.casErr
}
func fixture() (Binding, *jmem, *amem) {
	var x, y Hash
	x[0] = 1
	y[0] = 2
	b := Binding{Stage: Reservation, Invocation: "invoke", Resource: "resource", Transaction: "txn", Expected: State{Resource: "resource", Generation: 1, Hash: x, Transaction: "previous"}, Next: State{Resource: "resource", Generation: 2, Hash: y, Transaction: "txn"}, RequestHash: x}
	return b, &jmem{}, &amem{s: b.Expected}
}
func TestInitializationAndTransactionTuple(t *testing.T) {
	b, j, a := fixture()
	b.Stage = Initialization
	if e := (Machine{a, j}).Recover(context.Background(), b); e != nil || a.calls != 1 || a.lastTransaction != b.Transaction {
		t.Fatal(e)
	}
	b, j, a = fixture()
	var h Hash
	h[0] = 9
	a.s = State{Resource: b.Resource, Generation: 2, Hash: h, Transaction: "other"}
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrQuarantined) {
		t.Fatal(e)
	}
}
func TestUnknownCASOutcomesReadFirstNeverReplay(t *testing.T) {
	for _, applied := range []bool{true, false} {
		b, j, a := fixture()
		a.casErr = errors.New("unknown")
		a.apply = applied
		e := (Machine{a, j}).Recover(context.Background(), b)
		if applied {
			if e != nil {
				t.Fatal(e)
			}
		} else if !errors.Is(e, ErrUnavailable) {
			t.Fatal(e)
		}
		if a.calls != 1 || a.reads < 2 {
			t.Fatal(a.calls, a.reads)
		}
	}
}
func TestPreparedReplayAndInvocationQuarantine(t *testing.T) {
	b, j, a := fixture()
	j.ok = true
	j.i = Intent{b, Prepared}
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrUnavailable) || a.calls != 0 {
		t.Fatal(e)
	}
	b.Stage = InvocationStage
	j.i = Intent{b, Prepared}
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrQuarantined) || len(j.quarantined) != 1 || a.calls != 0 {
		t.Fatal(e)
	}
}
func TestCommittedRollbackAndIdempotentReplay(t *testing.T) {
	b, j, a := fixture()
	j.ok = true
	j.i = Intent{b, Committed}
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrQuarantined) {
		t.Fatal(e)
	}
	b, j, a = fixture()
	j.ok = true
	j.i = Intent{b, Committed}
	a.s = b.Next
	if e := (Machine{a, j}).Recover(context.Background(), b); e != nil {
		t.Fatal(e)
	}
}
func TestBindingConflictOriginalTargetAndMalformedRecord(t *testing.T) {
	b, j, a := fixture()
	orig := b
	orig.Resource = "original"
	orig.Expected.Resource = "original"
	orig.Next.Resource = "original"
	j.ok = true
	j.i = Intent{orig, Prepared}
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrQuarantined) || len(j.quarantined) != 2 || j.quarantined[0] != orig || j.quarantined[1] != b {
		t.Fatal(e)
	}
	b, j, a = fixture()
	j.ok = true
	j.i = Intent{Binding: Binding{}, Phase: Prepared}
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrUnavailable) || len(j.quarantined) != 0 {
		t.Fatal(e)
	}
}
func TestPhaseFailureReplayAndQuarantineFailure(t *testing.T) {
	b, j, a := fixture()
	j.phaseErr = errors.New("disk")
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	j.phaseErr = nil
	if e := (Machine{a, j}).Recover(context.Background(), b); e != nil || a.calls != 1 {
		t.Fatal(e)
	}
	b, j, a = fixture()
	var h Hash
	h[0] = 8
	a.s = State{Resource: b.Resource, Generation: 9, Hash: h, Transaction: "alien"}
	j.quarantineErr = errors.New("disk")
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
}
