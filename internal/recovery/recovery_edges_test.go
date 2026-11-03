package recovery

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type orderedJournal struct {
	*jmem
	log             *[]string
	loadErr, putErr error
}

func (j *orderedJournal) LoadIntent(c context.Context, id string) (Intent, error) {
	*j.log = append(*j.log, "load")
	if j.loadErr != nil {
		return Intent{}, j.loadErr
	}
	return j.jmem.LoadIntent(c, id)
}
func (j *orderedJournal) PutIntent(c context.Context, i Intent) error {
	*j.log = append(*j.log, "intent")
	if j.putErr != nil {
		return j.putErr
	}
	return j.jmem.PutIntent(c, i)
}
func (j *orderedJournal) SetPhase(c context.Context, id string, p Phase) error {
	*j.log = append(*j.log, "phase")
	return j.jmem.SetPhase(c, id, p)
}
func (j *orderedJournal) Quarantine(c context.Context, b Binding) error {
	*j.log = append(*j.log, "quarantine")
	return j.jmem.Quarantine(c, b)
}
func (j *orderedJournal) QuarantineConflict(c context.Context, stored, requested Binding) error {
	*j.log = append(*j.log, "quarantine-conflict")
	return j.jmem.QuarantineConflict(c, stored, requested)
}

type orderedAnchor struct {
	*amem
	log *[]string
}

func (a *orderedAnchor) Read(c context.Context, r string) (State, error) {
	*a.log = append(*a.log, "read")
	return a.amem.Read(c, r)
}
func (a *orderedAnchor) CompareAndSwap(c context.Context, o, n State, id string) error {
	*a.log = append(*a.log, "cas")
	return a.amem.CompareAndSwap(c, o, n, id)
}
func TestExactDurableOrder(t *testing.T) {
	b, j0, a0 := fixture()
	l := []string{}
	j := &orderedJournal{jmem: j0, log: &l}
	a := &orderedAnchor{a0, &l}
	if e := (Machine{a, j}).Recover(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	want := []string{"load", "intent", "read", "cas", "read", "phase", "read"}
	if !reflect.DeepEqual(l, want) {
		t.Fatal(l)
	}
}
func TestJournalErrorsAndReadFailureStopBeforeCAS(t *testing.T) {
	for _, caseName := range []string{"load", "put", "read"} {
		b, j0, a0 := fixture()
		l := []string{}
		j := &orderedJournal{jmem: j0, log: &l}
		a := &orderedAnchor{a0, &l}
		eio := errors.New("io")
		switch caseName {
		case "load":
			j.loadErr = eio
		case "put":
			j.putErr = eio
		case "read":
			a.readErr = eio
		}
		if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrUnavailable) || a.calls != 0 {
			t.Fatal(caseName, e, a.calls)
		}
	}
}
func TestCrashCutPoints(t *testing.T) {
	t.Run("after intent before CAS", func(t *testing.T) {
		b, j, a := fixture()
		j.ok = true
		j.i = Intent{b, Prepared}
		a.s = b.Expected
		if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrUnavailable) || a.calls != 0 {
			t.Fatal(e)
		}
	})
	t.Run("after CAS before phase", func(t *testing.T) {
		b, j, a := fixture()
		a.s = b.Next
		j.ok = true
		j.i = Intent{b, Prepared}
		if e := (Machine{a, j}).Recover(context.Background(), b); e != nil || j.i.Phase != Committed {
			t.Fatal(e)
		}
	})
	t.Run("after committed", func(t *testing.T) {
		b, j, a := fixture()
		a.s = b.Next
		j.ok = true
		j.i = Intent{b, Committed}
		if e := (Machine{a, j}).Recover(context.Background(), b); e != nil {
			t.Fatal(e)
		}
	})
}
func TestTamperedExpectedTupleQuarantinesResource(t *testing.T) {
	for _, field := range []string{"generation", "digest", "transaction"} {
		b, j, a := fixture()
		switch field {
		case "generation":
			a.s.Generation++
		case "digest":
			a.s.Hash[0] = 9
		case "transaction":
			a.s.Transaction = "wrong"
		}
		if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrQuarantined) || len(j.quarantined) != 1 || j.quarantined[0].Resource != b.Resource {
			t.Fatal(field, e)
		}
	}
}
func TestUnknownNotAppliedRestartDoesNotRetry(t *testing.T) {
	b, j, a := fixture()
	a.casErr = errors.New("uncertain")
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	a.casErr = nil
	if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrUnavailable) || a.calls != 1 {
		t.Fatal(e, a.calls)
	}
}
func TestMalformedPhasesQuarantine(t *testing.T) {
	for _, p := range []Phase{0, 99} {
		b, j, a := fixture()
		j.ok = true
		j.i = Intent{b, p}
		if e := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(e, ErrQuarantined) || len(j.quarantined) != 1 || a.calls != 0 {
			t.Fatal(p, e)
		}
	}
}
