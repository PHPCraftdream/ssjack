package recovery

import (
	"context"
	"errors"
	"testing"
)

// Applied errors retain the original intent and both blocks; unapplied errors retain neither block.
type conflictJournal struct {
	intents     map[string]Intent
	blocks      map[string]bool
	fail, apply bool
	calls       int
}

func (j *conflictJournal) LoadIntent(_ context.Context, id string) (Intent, error) {
	i, ok := j.intents[id]
	if !ok {
		return Intent{}, ErrNotFound
	}
	return i, nil
}
func (j *conflictJournal) PutIntent(_ context.Context, i Intent) error {
	if j.blocks[i.Binding.Resource] {
		return ErrConflict
	}
	for _, existing := range j.intents {
		if existing.Binding.Resource == i.Binding.Resource && existing.Phase == Quarantined {
			return ErrConflict
		}
	}
	if _, ok := j.intents[i.Binding.Invocation]; ok {
		return ErrConflict
	}
	j.intents[i.Binding.Invocation] = i
	return nil
}
func (j *conflictJournal) SetPhase(context.Context, string, Phase) error {
	return errors.New("unexpected phase")
}
func (j *conflictJournal) Quarantine(context.Context, Binding) error {
	return errors.New("unexpected single quarantine")
}
func (j *conflictJournal) QuarantineConflict(_ context.Context, stored, requested Binding) error {
	j.calls++
	if j.fail && !j.apply {
		return errors.New("unknown")
	}
	j.blocks[stored.Resource] = true
	j.blocks[requested.Resource] = true
	j.intents[stored.Invocation] = Intent{Binding: stored, Phase: Quarantined}
	if requested.Invocation != stored.Invocation {
		j.intents[requested.Invocation] = Intent{Binding: requested, Phase: Quarantined}
	}
	if j.fail {
		return errors.New("unknown")
	}
	return nil
}

type conflictAnchor struct{ *amem }

func (a conflictAnchor) CompareAndSwap(_ context.Context, old, next State, tx string) error {
	return a.amem.CompareAndSwap(context.Background(), old, next, tx)
}

func TestAtomicConflictQuarantinePreservesAndInterlocksBothBindings(t *testing.T) {
	stored, _, a := fixture()
	requested := stored
	stored.Resource = "resource-original"
	stored.Expected.Resource, stored.Next.Resource = stored.Resource, stored.Resource
	requested.Invocation = stored.Invocation
	requested.Resource = "resource-requested"
	requested.Transaction = "requested-tx"
	requested.Expected.Resource, requested.Next.Resource = requested.Resource, requested.Resource
	requested.Next.Transaction = requested.Transaction
	for _, appliedError := range []bool{false, true} {
		j := &conflictJournal{intents: map[string]Intent{"invoke": {Binding: stored, Phase: Prepared}}, blocks: map[string]bool{}, fail: true, apply: appliedError}
		m := Machine{Anchor: conflictAnchor{a}, Journal: j}
		if err := m.Recover(context.Background(), requested); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if j.calls != 1 {
			t.Fatal(j.calls)
		}
		if appliedError {
			if !j.blocks[stored.Resource] || !j.blocks[requested.Resource] || j.intents[stored.Invocation].Binding != stored {
				t.Fatal(j)
			}
			for _, b := range []Binding{stored, requested} {
				attempt := b
				attempt.Invocation += "-retry"
				if err := m.Recover(context.Background(), attempt); !errors.Is(err, ErrUnavailable) {
					t.Fatal(err)
				}
				if err := j.PutIntent(context.Background(), Intent{Binding: attempt, Phase: Prepared}); !errors.Is(err, ErrConflict) {
					t.Fatal(err)
				}
			}
		} else if j.blocks[stored.Resource] || j.blocks[requested.Resource] {
			t.Fatal(j.blocks)
		}
	}
	j := &conflictJournal{intents: map[string]Intent{"invoke": {Binding: stored, Phase: Prepared}}, blocks: map[string]bool{}}
	m := Machine{Anchor: conflictAnchor{a}, Journal: j}
	if err := m.Recover(context.Background(), requested); !errors.Is(err, ErrQuarantined) {
		t.Fatal(err)
	}
	if j.intents[stored.Invocation].Binding != stored || !j.blocks[stored.Resource] || !j.blocks[requested.Resource] {
		t.Fatal(j)
	}
	for _, b := range []Binding{stored, requested} {
		attempt := b
		attempt.Invocation += "-new"
		before := a.calls
		if err := m.Recover(context.Background(), attempt); !errors.Is(err, ErrUnavailable) || a.calls != before {
			t.Fatal(err, a.calls, before)
		}
		if err := j.PutIntent(context.Background(), Intent{Binding: attempt, Phase: Prepared}); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
}

func TestCASUsesTransactionRatherThanInvocation(t *testing.T) {
	b, j, a := fixture()
	b.Invocation = "different-invocation"
	if err := (Machine{Anchor: a, Journal: j}).Recover(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if a.lastTransaction != b.Transaction {
		t.Fatal(a.lastTransaction, b.Transaction)
	}
}
