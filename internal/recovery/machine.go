package recovery

import (
	"context"
	"errors"
)

type Hash [32]byte
type State struct {
	Resource    string
	Generation  uint64
	Hash        Hash
	Transaction string
}
type Stage uint8

const (
	Initialization Stage = iota + 1
	Reservation
	InvocationStage
)

type Binding struct {
	Stage       Stage
	Invocation  string
	Resource    string
	Expected    State
	Next        State
	RequestHash Hash
	Transaction string
}
type Phase uint8

const (
	Prepared Phase = iota + 1
	Committed
	Quarantined
)

type Intent struct {
	Binding Binding
	Phase   Phase
}

var ErrNotFound = errors.New("intent proven absent")
var ErrUnavailable = errors.New("recovery unavailable")
var ErrQuarantined = errors.New("invocation or resource quarantined")
var ErrConflict = errors.New("binding or authoritative state conflicts")

// Journal implementations must atomically serialize and gate intent mutations. The caller
// must hold exclusive ownership of invocation and resource (including conflicting stored
// resources) from before LoadIntent through return. PutIntent returns nil only after durable
// creation of exactly Prepared. SetPhase returns nil only after durable Prepared->Committed
// (or confirming already Committed); Quarantine returns nil only after durably blocking both
// identities. QuarantineConflict atomically preserves the original intent evidence and durably
// blocks both bindings; it must not overwrite the stored binding. Every mutation must be
// conditional on its prior state, linearizable, and fenced against late completion
// after an error/timeout or a subsequent mutation. An error gives no outcome guarantee;
// failed QuarantineConflict requires the caller to maintain a global admission fence until
// external linearizable reconciliation proves both identities blocked. The error itself does
// not establish a durable block. ErrNotFound means proven absence only.
type Journal interface {
	LoadIntent(context.Context, string) (Intent, error)
	PutIntent(context.Context, Intent) error
	SetPhase(context.Context, string, Phase) error
	Quarantine(context.Context, Binding) error
	QuarantineConflict(context.Context, Binding, Binding) error
}

// Read is authenticated and linearizable. CAS must atomically compare the entire old State
// tuple and advance only to the entire new tuple, monotonically by generation, never overwrite
// a newer/conflicting state, and return nil only when the exact update is durable. A timed-out
// CAS must not complete after a later Read has returned (including a read of the old tuple);
// otherwise this protocol is unsafe and must not be used.
// CompareAndSwap's fourth argument is the binding transaction ID. The trusted adapter must
// enforce its immutable mapping to the full binding; this interface does not establish it.
type Anchor interface {
	Read(context.Context, string) (State, error)
	CompareAndSwap(context.Context, State, State, string) error
}
type Machine struct {
	Anchor  Anchor
	Journal Journal
}

func (m Machine) Recover(ctx context.Context, b Binding) error {
	if !valid(b) || m.Anchor == nil || m.Journal == nil {
		return ErrUnavailable
	}
	i, err := m.Journal.LoadIntent(ctx, b.Invocation)
	existing := err == nil
	if existing {
		if !valid(i.Binding) {
			return ErrUnavailable
		}
		if i.Binding != b {
			return m.quarantineConflict(ctx, i.Binding, b)
		}
		switch i.Phase {
		case Quarantined:
			return ErrQuarantined
		case Prepared, Committed:
		default:
			return m.quarantine(ctx, i.Binding)
		}
		if i.Binding.Stage == InvocationStage {
			return m.quarantine(ctx, i.Binding)
		}
	} else if errors.Is(err, ErrNotFound) {
		if b.Stage == InvocationStage {
			return ErrUnavailable
		}
		if err = m.Journal.PutIntent(ctx, Intent{Binding: b, Phase: Prepared}); err != nil {
			return ErrUnavailable
		}
		i = Intent{Binding: b, Phase: Prepared}
	} else {
		return ErrUnavailable
	}
	state, err := m.Anchor.Read(ctx, b.Resource)
	if err != nil {
		return ErrUnavailable
	}
	if state == b.Next {
		if state.Transaction != b.Transaction {
			return m.quarantine(ctx, b)
		}
		if i.Phase == Committed {
			return nil
		}
		return m.commit(ctx, b)
	}
	if state == b.Expected {
		if i.Phase == Committed {
			return m.quarantine(ctx, b)
		}
		if existing {
			return ErrUnavailable
		}
	} else {
		return m.quarantine(ctx, b)
	}
	if i.Phase == Committed {
		return m.quarantine(ctx, b)
	}
	if m.Anchor.CompareAndSwap(ctx, b.Expected, b.Next, b.Transaction) != nil {
		// Unknown outcome: read first, never automatically replay.
		state, err = m.Anchor.Read(ctx, b.Resource)
		if err != nil {
			return ErrUnavailable
		}
		if state == b.Next && state.Transaction == b.Transaction {
			return m.commit(ctx, b)
		}
		if state == b.Expected {
			return ErrUnavailable
		}
		return m.quarantine(ctx, b)
	}
	state, err = m.Anchor.Read(ctx, b.Resource)
	if err != nil {
		return ErrUnavailable
	}
	if state != b.Next || state.Transaction != b.Transaction {
		return m.quarantine(ctx, b)
	}
	return m.commit(ctx, b)
}
func (m Machine) commit(ctx context.Context, b Binding) error {
	if err := m.Journal.SetPhase(ctx, b.Invocation, Committed); err != nil {
		return ErrUnavailable
	}
	s, err := m.Anchor.Read(ctx, b.Resource)
	if err != nil {
		return ErrUnavailable
	}
	if s != b.Next || s.Transaction != b.Transaction {
		return m.quarantine(ctx, b)
	}
	return nil
}
func (m Machine) quarantine(ctx context.Context, b Binding) error {
	if !valid(b) {
		return ErrUnavailable
	}
	if err := m.Journal.Quarantine(ctx, b); err != nil {
		return ErrUnavailable
	}
	return ErrQuarantined
}
func (m Machine) quarantineConflict(ctx context.Context, stored, requested Binding) error {
	if err := m.Journal.QuarantineConflict(ctx, stored, requested); err != nil {
		return ErrUnavailable
	}
	return ErrQuarantined
}
func valid(b Binding) bool {
	id := func(s string) bool {
		if len(s) == 0 || len(s) > 128 {
			return false
		}
		for _, c := range []byte(s) {
			if c < 0x21 || c > 0x7e {
				return false
			}
		}
		return true
	}
	transaction := func(s string) bool { return s == "" || id(s) }
	return (b.Stage == Initialization || b.Stage == Reservation || b.Stage == InvocationStage) && id(b.Invocation) && id(b.Resource) && id(b.Transaction) && b.Expected.Resource == b.Resource && b.Next.Resource == b.Resource && b.Next.Transaction == b.Transaction && transaction(b.Expected.Transaction) && b.Expected.Transaction != b.Transaction && ((b.Expected.Generation == 0 && b.Expected.Transaction == "") || (b.Expected.Generation > 0 && b.Expected.Transaction != "")) && b.Expected.Generation != ^uint64(0) && b.Next.Generation == b.Expected.Generation+1 && b.Expected.Hash != b.Next.Hash
}
