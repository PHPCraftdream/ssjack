package recovery

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// lockedResources models the required exclusive invocation/resource ownership.
type lockedResources struct {
	mu    sync.Mutex
	j     *jmem
	a     *amem
	owned bool
}

type lockedJournal struct{ *lockedResources }
type lockedAnchor struct{ *lockedResources }

func (r *lockedResources) acquire() { r.mu.Lock(); r.owned = true }
func (r *lockedResources) release() { r.owned = false; r.mu.Unlock() }
func (j lockedJournal) check() {
	if !j.owned {
		panic("journal access without resource lock")
	}
}
func (a lockedAnchor) check() {
	if !a.owned {
		panic("anchor access without resource lock")
	}
}
func (j lockedJournal) LoadIntent(c context.Context, id string) (Intent, error) {
	j.check()
	return j.j.LoadIntent(c, id)
}
func (j lockedJournal) PutIntent(c context.Context, i Intent) error {
	j.check()
	return j.j.PutIntent(c, i)
}
func (j lockedJournal) SetPhase(c context.Context, id string, p Phase) error {
	j.check()
	return j.j.SetPhase(c, id, p)
}
func (j lockedJournal) Quarantine(c context.Context, b Binding) error {
	j.check()
	return j.j.Quarantine(c, b)
}
func (j lockedJournal) QuarantineConflict(c context.Context, stored, requested Binding) error {
	j.check()
	return j.j.QuarantineConflict(c, stored, requested)
}
func (a lockedAnchor) Read(c context.Context, id string) (State, error) {
	a.check()
	return a.a.Read(c, id)
}
func (a lockedAnchor) CompareAndSwap(c context.Context, old, next State, id string) error {
	a.check()
	return a.a.CompareAndSwap(c, old, next, id)
}

func TestResourceInterlockCoversRecovery(t *testing.T) {
	b, j, a := fixture()
	r := &lockedResources{j: j, a: a}
	r.acquire()
	err := (Machine{Anchor: lockedAnchor{r}, Journal: lockedJournal{r}}).Recover(context.Background(), b)
	r.release()
	if err != nil || r.a.calls != 1 || r.j.i.Phase != Committed {
		t.Fatal(err, r.a.calls, r.j.i.Phase)
	}
}

type uncertainJournal struct {
	*jmem
	putAfterError, phaseAfterError bool
}

func (j *uncertainJournal) PutIntent(c context.Context, i Intent) error {
	if j.putAfterError {
		_ = j.jmem.PutIntent(c, i)
		return errors.New("put outcome unknown")
	}
	return j.jmem.PutIntent(c, i)
}
func (j *uncertainJournal) SetPhase(c context.Context, id string, p Phase) error {
	if j.phaseAfterError {
		_ = j.jmem.SetPhase(c, id, p)
		return errors.New("phase outcome unknown")
	}
	return j.jmem.SetPhase(c, id, p)
}

func TestMutationApplyThenErrorReconcilesWithoutBlindRetry(t *testing.T) {
	t.Run("put", func(t *testing.T) {
		b, j, a := fixture()
		u := &uncertainJournal{jmem: j, putAfterError: true}
		if err := (Machine{a, u}).Recover(context.Background(), b); !errors.Is(err, ErrUnavailable) || a.calls != 0 || !j.ok {
			t.Fatal(err, a.calls, j.ok)
		}
		u.putAfterError = false
		if err := (Machine{a, u}).Recover(context.Background(), b); !errors.Is(err, ErrUnavailable) || a.calls != 0 {
			t.Fatal(err, a.calls)
		}
	})
	t.Run("phase", func(t *testing.T) {
		b, j, a := fixture()
		u := &uncertainJournal{jmem: j, phaseAfterError: true}
		if err := (Machine{a, u}).Recover(context.Background(), b); !errors.Is(err, ErrUnavailable) || a.calls != 1 || j.i.Phase != Committed {
			t.Fatal(err, a.calls, j.i.Phase)
		}
		u.phaseAfterError = false
		if err := (Machine{a, u}).Recover(context.Background(), b); err != nil || a.calls != 1 {
			t.Fatal(err, a.calls)
		}
	})
}

func TestReadFailuresAfterCASAndCommitFailClosed(t *testing.T) {
	for _, failAt := range []int{2, 3} {
		b, j, a := fixture()
		base := a
		f := &failReadAnchor{amem: base, failAt: failAt}
		err := (Machine{f, j}).Recover(context.Background(), b)
		if !errors.Is(err, ErrUnavailable) || base.calls != 1 {
			t.Fatal(failAt, err, base.calls)
		}
	}
}

type failReadAnchor struct {
	*amem
	failAt int
}

func (a *failReadAnchor) Read(c context.Context, id string) (State, error) {
	a.reads++
	if a.reads == a.failAt {
		return State{}, errors.New("read failure")
	}
	return a.s, nil
}

func TestRetryIdempotenceAndInvalidPreviousTuple(t *testing.T) {
	b, j, a := fixture()
	m := Machine{a, j}
	if err := m.Recover(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(context.Background(), b); err != nil || a.calls != 1 {
		t.Fatal(err, a.calls)
	}
	for _, mutate := range []func(*Binding){func(b *Binding) { b.Expected.Transaction = "" }, func(b *Binding) { b.Expected.Generation = 0 }} {
		bad, jj, aa := fixture()
		mutate(&bad)
		if err := (Machine{aa, jj}).Recover(context.Background(), bad); !errors.Is(err, ErrUnavailable) || aa.calls != 0 {
			t.Fatal(err, aa.calls)
		}
	}
}

func TestGenerationMaximumRejected(t *testing.T) {
	b, j, a := fixture()
	b.Expected.Generation = ^uint64(0)
	b.Expected.Transaction = "previous"
	if err := (Machine{a, j}).Recover(context.Background(), b); !errors.Is(err, ErrUnavailable) || a.calls != 0 {
		t.Fatal(err, a.calls)
	}
}

type multiJournal struct {
	intents map[string]Intent
	blocked map[string]bool
}

func (j *multiJournal) LoadIntent(_ context.Context, id string) (Intent, error) {
	i, ok := j.intents[id]
	if !ok {
		return Intent{}, ErrNotFound
	}
	return i, nil
}
func (j *multiJournal) PutIntent(_ context.Context, i Intent) error {
	b := i.Binding
	if j.blocked[b.Resource] || j.intents[b.Invocation].Binding.Invocation != "" {
		return ErrConflict
	}
	for _, existing := range j.intents {
		if existing.Binding.Resource == b.Resource && existing.Phase == Quarantined {
			return ErrConflict
		}
	}
	j.intents[b.Invocation] = i
	return nil
}
func (j *multiJournal) SetPhase(_ context.Context, id string, p Phase) error {
	i, ok := j.intents[id]
	if !ok {
		return ErrNotFound
	}
	i.Phase = p
	j.intents[id] = i
	return nil
}
func (j *multiJournal) Quarantine(_ context.Context, b Binding) error {
	j.blocked[b.Resource] = true
	if current, ok := j.intents[b.Invocation]; ok {
		current.Phase = Quarantined
		j.intents[b.Invocation] = current
	} else {
		j.intents[b.Invocation] = Intent{Binding: b, Phase: Quarantined}
	}
	return nil
}
func (j *multiJournal) QuarantineConflict(_ context.Context, stored, requested Binding) error {
	j.blocked[stored.Resource] = true
	j.blocked[requested.Resource] = true
	// Never replace the stored binding under its invocation key.
	if original, ok := j.intents[stored.Invocation]; ok {
		original.Phase = Quarantined
		j.intents[stored.Invocation] = original
	} else {
		j.intents[stored.Invocation] = Intent{Binding: stored, Phase: Quarantined}
	}
	if requested.Invocation != stored.Invocation {
		j.intents[requested.Invocation] = Intent{Binding: requested, Phase: Quarantined}
	}
	return nil
}

func TestQuarantinedResourceRejectsOtherInvocation(t *testing.T) {
	b, _, a := fixture()
	j := &multiJournal{intents: map[string]Intent{}, blocked: map[string]bool{}}
	var alien Hash
	alien[0] = 7
	a.s = State{Resource: b.Resource, Generation: 7, Hash: alien, Transaction: "alien"}
	if err := (Machine{Anchor: a, Journal: j}).Recover(context.Background(), b); !errors.Is(err, ErrQuarantined) || !j.blocked[b.Resource] {
		t.Fatal(err, j.blocked)
	}
	second := b
	second.Invocation = "second-invocation"
	second.Transaction = "second-transaction"
	second.Next.Transaction = second.Transaction
	before := a.calls
	if err := (Machine{Anchor: a, Journal: j}).Recover(context.Background(), second); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err, a.calls, before)
	}
}

func TestGenesisAndExpectedTransactionValidation(t *testing.T) {
	b, j, a := fixture()
	b.Stage = Initialization
	b.Expected.Generation = 0
	b.Expected.Transaction = ""
	b.Next.Generation = 1
	a.s = b.Expected
	if err := (Machine{a, j}).Recover(context.Background(), b); err != nil || a.calls != 1 {
		t.Fatal(err, a.calls)
	}
	for _, transaction := range []string{strings.Repeat("a", 129), "bad\ntransaction"} {
		bad, jj, aa := fixture()
		bad.Expected.Transaction = transaction
		if err := (Machine{aa, jj}).Recover(context.Background(), bad); !errors.Is(err, ErrUnavailable) || aa.calls != 0 {
			t.Fatal(err, aa.calls)
		}
	}
}

func TestSameIdentifierAcrossBindingFieldsAllowed(t *testing.T) {
	b, j, a := fixture()
	b.Invocation = "same"
	b.Resource = "same"
	b.Expected.Resource = "same"
	b.Next.Resource = "same"
	b.Transaction = "same"
	b.Expected.Transaction = "previous"
	b.Next.Transaction = "same"
	a.s = b.Expected
	if err := (Machine{a, j}).Recover(context.Background(), b); err != nil || a.calls != 1 {
		t.Fatal(err, a.calls)
	}
}
