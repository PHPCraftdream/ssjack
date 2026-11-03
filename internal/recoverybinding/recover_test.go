package recoverybinding_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
	"github.com/PHPCraftdream/ssjack/internal/recoverybinding"
)

// These adapters model transitions only, not authenticated or durable storage.
type anchor struct {
	state recovery.State
	calls int
	cas   int
}

func (a *anchor) Read(context.Context, string) (recovery.State, error) {
	a.calls++
	return a.state, nil
}
func (a *anchor) CompareAndSwap(_ context.Context, old, next recovery.State, transaction string) error {
	a.calls++
	a.cas++
	if a.state != old || next.Transaction != transaction {
		return recovery.ErrConflict
	}
	a.state = next
	return nil
}

type journal struct {
	intent *recovery.Intent
	calls  int
}

func (j *journal) LoadIntent(context.Context, string) (recovery.Intent, error) {
	j.calls++
	if j.intent == nil {
		return recovery.Intent{}, recovery.ErrNotFound
	}
	return *j.intent, nil
}
func (j *journal) PutIntent(_ context.Context, value recovery.Intent) error {
	j.calls++
	if j.intent != nil || value.Phase != recovery.Prepared {
		return recovery.ErrUnavailable
	}
	j.intent = &value
	return nil
}
func (j *journal) SetPhase(_ context.Context, invocation string, phase recovery.Phase) error {
	j.calls++
	if j.intent == nil || invocation != j.intent.Binding.Invocation || phase != recovery.Committed || (j.intent.Phase != recovery.Prepared && j.intent.Phase != recovery.Committed) {
		return recovery.ErrUnavailable
	}
	j.intent.Phase = phase
	return nil
}
func (j *journal) Quarantine(_ context.Context, b recovery.Binding) error {
	j.calls++
	j.intent = &recovery.Intent{Binding: b, Phase: recovery.Quarantined}
	return nil
}
func (j *journal) QuarantineConflict(context.Context, recovery.Binding, recovery.Binding) error {
	j.calls++
	return recovery.ErrUnavailable
}

func machine(b recovery.Binding) (recovery.Machine, *anchor, *journal) {
	a, j := &anchor{state: b.Expected}, &journal{}
	return recovery.Machine{Anchor: a, Journal: j}, a, j
}

func TestStrictRecoverRejectsBeforeStorage(t *testing.T) {
	for name, mutate := range map[string]func(*recovery.Binding){
		"request-tampering":    func(b *recovery.Binding) { b.RequestHash[0] ^= 1 },
		"invocation-tampering": func(b *recovery.Binding) { b.Invocation = "different" },
		"legacy":               func(b *recovery.Binding) { b.Transaction, b.Next.Transaction = "legacy", "legacy" },
	} {
		t.Run(name, func(t *testing.T) {
			b := committed(t)
			mutate(&b)
			if !recovery.ValidBinding(b) {
				t.Fatal("strict rejection masked by invalid legacy structure")
			}
			m, a, j := machine(b)
			if !errors.Is(recoverybinding.Recover(context.Background(), m, b), recovery.ErrUnavailable) || a.calls != 0 || j.calls != 0 {
				t.Fatal("invalid commitment reached storage")
			}
		})
	}
	b := committed(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		m, a, j := machine(b)
		if !errors.Is(recoverybinding.Recover(ctx, m, b), recovery.ErrUnavailable) || a.calls != 0 || j.calls != 0 {
			t.Fatal("invalid context reached storage")
		}
	}
}

func TestStrictRecoveryAndLegacyCompatibility(t *testing.T) {
	b := committed(t)
	m, a, j := machine(b)
	if err := recoverybinding.Recover(context.Background(), m, b); err != nil {
		t.Fatal(err)
	}
	if a.cas != 1 || a.state != b.Next || j.intent == nil || j.intent.Binding != b || j.intent.Phase != recovery.Committed {
		t.Fatal("valid committed binding did not reach exact next state")
	}
	if err := recoverybinding.Recover(context.Background(), m, b); err != nil || a.cas != 1 {
		t.Fatalf("committed recovery replayed CAS: %v", err)
	}

	legacy := b
	legacy.Transaction, legacy.Next.Transaction = "legacy", "legacy"
	m, a, j = machine(legacy)
	if err := m.Recover(context.Background(), legacy); err != nil || a.state != legacy.Next || j.intent == nil || j.intent.Phase != recovery.Committed {
		t.Fatalf("legacy entry point was changed: %v", err)
	}
}

func TestInvocationIntentStillQuarantinesWithoutCAS(t *testing.T) {
	value := input()
	value.Stage = recovery.InvocationStage
	b, err := recoverybinding.New(value)
	if err != nil {
		t.Fatal(err)
	}
	m, a, j := machine(b)
	j.intent = &recovery.Intent{Binding: b, Phase: recovery.Prepared}
	if err := recoverybinding.Recover(context.Background(), m, b); !errors.Is(err, recovery.ErrQuarantined) || a.calls != 0 || j.intent.Phase != recovery.Quarantined {
		t.Fatalf("invocation recovery changed: %v", err)
	}
}

func TestPriorTransactionBoundary(t *testing.T) {
	b := input()
	b.Expected.Transaction = strings.Repeat("~", 128)
	value, err := recoverybinding.New(b)
	if err != nil || recoverybinding.Validate(value) != nil {
		t.Fatalf("maximum printable prior transaction: %v", err)
	}
	b.Expected.Transaction += "~"
	if _, err := recoverybinding.New(b); !errors.Is(err, recoverybinding.ErrInvalid) {
		t.Fatal("oversized prior transaction admitted")
	}
}
