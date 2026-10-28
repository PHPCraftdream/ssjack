//go:build linux

package recoveryintegration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
	"github.com/PHPCraftdream/ssjack/internal/recoveryjournal"
)

type anchor struct {
	state          recovery.State
	reads, swaps   int
	tx             string
	readErr        error
	readErrAt      int
	casErr         error
	applyOnError   bool
	events         *[]string
	journalPath    string
	preparedOnDisk bool
	transactions   map[string]recovery.Binding
}

func (a *anchor) Read(_ context.Context, resource string) (recovery.State, error) {
	a.reads++
	if a.events != nil {
		*a.events = append(*a.events, "read")
	}
	if a.readErr != nil && (a.readErrAt == 0 || a.reads == a.readErrAt) {
		return recovery.State{}, a.readErr
	}
	if resource != a.state.Resource {
		return recovery.State{}, errors.New("wrong resource")
	}
	return a.state, nil
}
func (a *anchor) CompareAndSwap(_ context.Context, old, next recovery.State, tx string) error {
	a.swaps++
	a.tx = tx
	if a.events != nil {
		*a.events = append(*a.events, "cas")
	}
	raw, err := os.ReadFile(a.journalPath)
	a.preparedOnDisk = err == nil && bytes.Contains(raw, []byte(`"Phase":1`)) && bytes.Contains(raw, []byte(tx))
	if a.state != old || next.Resource != old.Resource || next.Generation != old.Generation+1 || next.Generation <= a.state.Generation {
		return recovery.ErrConflict
	}
	if prior, ok := a.transactions[tx]; !ok || prior.Transaction != tx || prior.Resource != next.Resource || prior.Expected != old || prior.Next != next {
		return recovery.ErrConflict
	}
	if a.casErr == nil || a.applyOnError {
		a.state = next
	}
	return a.casErr
}
func (a *anchor) bind(b recovery.Binding) error {
	if a.transactions == nil {
		a.transactions = make(map[string]recovery.Binding)
	}
	if prior, ok := a.transactions[b.Transaction]; ok && prior != b {
		return recovery.ErrConflict
	}
	a.transactions[b.Transaction] = b
	return nil
}
func admittedRecover(ctx context.Context, a *anchor, m recovery.Machine, b recovery.Binding) error {
	if err := a.bind(b); err != nil {
		return err
	}
	return m.Recover(ctx, b)
}
func binding() recovery.Binding {
	oldHash, nextHash := sha256.Sum256([]byte("old")), sha256.Sum256([]byte("new"))
	old := recovery.State{Resource: "disk-A", Generation: 4, Hash: oldHash, Transaction: "prior"}
	next := recovery.State{Resource: "disk-A", Generation: 5, Hash: nextHash, Transaction: "tx-131"}
	return recovery.Binding{Stage: recovery.Reservation, Invocation: "invoke-131", Resource: "disk-A", Expected: old, Next: next, RequestHash: sha256.Sum256([]byte("request")), Transaction: "tx-131"}
}
func setup(t *testing.T) (*recoveryjournal.Journal, string, *anchor, recovery.Binding) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "journal")
	j, err := recoveryjournal.Initialize(root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b := binding()
	return j, root, &anchor{state: b.Expected, journalPath: filepath.Join(root, "journal.json"), transactions: map[string]recovery.Binding{b.Transaction: b}}, b
}
func TestRealJournalMachineIntegration(t *testing.T) {
	t.Run("ordering commit repeat and bytes", func(t *testing.T) {
		j, root, a, b := setup(t)
		events := []string{}
		a.events = &events
		m := recovery.Machine{Anchor: a, Journal: j}
		if err := m.Recover(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		if a.swaps != 1 || a.tx != b.Transaction || a.state != b.Next || !a.preparedOnDisk {
			t.Fatalf("anchor=%+v", a)
		}
		if !reflect.DeepEqual(events, []string{"read", "cas", "read", "read"}) {
			t.Fatalf("events=%v", events)
		}
		got, err := j.LoadIntent(context.Background(), b.Invocation)
		if err != nil || got.Binding != b || got.Phase != recovery.Committed {
			t.Fatalf("intent=%+v %v", got, err)
		}
		raw, err := os.ReadFile(filepath.Join(root, "journal.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte(`"Phase":2`)) || !bytes.Contains(raw, []byte(b.Transaction)) {
			t.Fatalf("journal bytes: %s", raw)
		}
		before := a.swaps
		if err = m.Recover(context.Background(), b); err != nil || a.swaps != before {
			t.Fatalf("repeat %v swaps=%d", err, a.swaps)
		}
	})
	t.Run("uncertain CAS not applied is read first, never replayed", func(t *testing.T) {
		j, _, a, b := setup(t)
		events := []string{}
		a.events = &events
		a.casErr = errors.New("uncertain")
		err := (recovery.Machine{Anchor: a, Journal: j}).Recover(context.Background(), b)
		if !errors.Is(err, recovery.ErrUnavailable) || a.swaps != 1 || a.reads != 2 || !a.preparedOnDisk || !reflect.DeepEqual(events, []string{"read", "cas", "read"}) {
			t.Fatalf("err=%v swaps=%d reads=%d events=%v", err, a.swaps, a.reads, events)
		}
		got, err := j.LoadIntent(context.Background(), b.Invocation)
		if err != nil || got.Phase != recovery.Prepared {
			t.Fatalf("intent=%+v err=%v", got, err)
		}
		before := a.swaps
		err = (recovery.Machine{Anchor: a, Journal: j}).Recover(context.Background(), b)
		if !errors.Is(err, recovery.ErrUnavailable) || a.swaps != before || !reflect.DeepEqual(events, []string{"read", "cas", "read", "read"}) {
			t.Fatalf("second recovery err=%v swaps=%d events=%v", err, a.swaps, events)
		}
	})
	t.Run("uncertain applied CAS reconciles", func(t *testing.T) {
		j, _, a, b := setup(t)
		a.casErr = errors.New("uncertain")
		a.applyOnError = true
		if err := (recovery.Machine{Anchor: a, Journal: j}).Recover(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		got, err := j.LoadIntent(context.Background(), b.Invocation)
		if err != nil || got.Phase != recovery.Committed {
			t.Fatalf("intent=%+v err=%v", got, err)
		}
	})
	t.Run("conflicting anchor quarantines", func(t *testing.T) {
		j, _, a, b := setup(t)
		a.state = recovery.State{Resource: b.Resource, Generation: 9, Hash: sha256.Sum256([]byte("alien")), Transaction: "alien"}
		if err := (recovery.Machine{Anchor: a, Journal: j}).Recover(context.Background(), b); !errors.Is(err, recovery.ErrQuarantined) {
			t.Fatal(err)
		}
		if _, err := j.LoadIntent(context.Background(), b.Invocation); !errors.Is(err, recovery.ErrQuarantined) {
			t.Fatal(err)
		}
		if a.swaps != 0 {
			t.Fatal(a.swaps)
		}
	})
	t.Run("conflicting bindings block both identities", func(t *testing.T) {
		j, _, a, stored := setup(t)
		requested := binding()
		requested.Resource = "disk-B"
		requested.Invocation = stored.Invocation
		requested.Expected = recovery.State{Resource: "disk-B", Generation: 4, Hash: sha256.Sum256([]byte("old-B")), Transaction: "prior-B"}
		requested.Next = recovery.State{Resource: "disk-B", Generation: 5, Hash: sha256.Sum256([]byte("new-B")), Transaction: requested.Transaction}
		if err := j.PutIntent(context.Background(), recovery.Intent{Binding: stored, Phase: recovery.Prepared}); err != nil {
			t.Fatal(err)
		}
		if err := (recovery.Machine{Anchor: a, Journal: j}).Recover(context.Background(), requested); !errors.Is(err, recovery.ErrQuarantined) {
			t.Fatalf("got %v", err)
		}
		raw, err := os.ReadFile(a.journalPath)
		if err != nil {
			t.Fatal(err)
		}
		var disk struct {
			Records []struct {
				Intent  recovery.Intent    `json:"intent"`
				Blocked []recovery.Binding `json:"blocked"`
			} `json:"records"`
		}
		if err := json.Unmarshal(raw, &disk); err != nil {
			t.Fatal(err)
		}
		if len(disk.Records) != 1 || disk.Records[0].Intent.Binding != stored || disk.Records[0].Intent.Phase != recovery.Quarantined || len(disk.Records[0].Blocked) != 2 || disk.Records[0].Blocked[0] != stored || disk.Records[0].Blocked[1] != requested {
			t.Fatalf("unexpected durable conflict evidence: %+v", disk.Records)
		}
		for _, blocked := range []recovery.Binding{stored, requested} {
			candidate := blocked
			candidate.Invocation += "-retry"
			if err := j.PutIntent(context.Background(), recovery.Intent{Binding: candidate, Phase: recovery.Prepared}); !errors.Is(err, recovery.ErrQuarantined) {
				t.Fatalf("%s not blocked: %v", blocked.Resource, err)
			}
		}
	})
	t.Run("CAS read-back error", func(t *testing.T) {
		j, _, a, b := setup(t)
		events := []string{}
		a.events = &events
		a.casErr = errors.New("uncertain")
		a.readErr = errors.New("read-back failure")
		a.readErrAt = 2
		if err := (recovery.Machine{Anchor: a, Journal: j}).Recover(context.Background(), b); !errors.Is(err, recovery.ErrUnavailable) {
			t.Fatal(err)
		}
		if a.swaps != 1 || a.reads != 2 || !a.preparedOnDisk || !reflect.DeepEqual(events, []string{"read", "cas", "read"}) {
			t.Fatalf("swaps=%d reads=%d prepared=%v events=%v", a.swaps, a.reads, a.preparedOnDisk, events)
		}
	})
	t.Run("cancel before mutation", func(t *testing.T) {
		j, _, a, b := setup(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := (recovery.Machine{Anchor: a, Journal: j}).Recover(ctx, b); !errors.Is(err, recovery.ErrUnavailable) {
			t.Fatal(err)
		}
		if _, err := j.LoadIntent(context.Background(), b.Invocation); !errors.Is(err, recovery.ErrNotFound) {
			t.Fatal(err)
		}
		if a.reads != 0 || a.swaps != 0 {
			t.Fatal(a)
		}
	})
	t.Run("transaction reuse with changed full binding is rejected", func(t *testing.T) {
		j, _, a, b := setup(t)
		if err := admittedRecover(context.Background(), a, recovery.Machine{Anchor: a, Journal: j}, b); err != nil {
			t.Fatal(err)
		}
		gotBefore, err := j.LoadIntent(context.Background(), b.Invocation)
		if err != nil || gotBefore.Binding != b || gotBefore.Phase != recovery.Committed {
			t.Fatalf("original intent before rejected dispatch: %+v err=%v", gotBefore, err)
		}
		changed := b
		changed.Invocation = "invoke-reuse"
		changed.RequestHash = sha256.Sum256([]byte("different request"))
		baselineReads, baselineSwaps := a.reads, a.swaps
		if err := admittedRecover(context.Background(), a, recovery.Machine{Anchor: a, Journal: j}, changed); !errors.Is(err, recovery.ErrConflict) {
			t.Fatalf("changed binding passed admission: %v", err)
		}
		if gotAfter, err := j.LoadIntent(context.Background(), b.Invocation); err != nil || gotAfter != gotBefore {
			t.Fatalf("journal mutated after rejected admission: %+v err=%v", gotAfter, err)
		}
		if _, err := j.LoadIntent(context.Background(), changed.Invocation); !errors.Is(err, recovery.ErrNotFound) {
			t.Fatalf("changed invocation journal entry: %v", err)
		}
		if a.state != b.Next || a.reads != baselineReads || a.swaps != baselineSwaps {
			t.Fatalf("anchor touched after rejected admission: %+v", a)
		}
	})
	t.Run("out-of-order anchor rejects stale CAS after Machine advances", func(t *testing.T) {
		j, _, a, b := setup(t)
		if err := (recovery.Machine{Anchor: a, Journal: j}).Recover(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		staleNext := recovery.State{Resource: b.Resource, Generation: b.Expected.Generation + 1, Hash: sha256.Sum256([]byte("stale")), Transaction: b.Transaction}
		if err := a.CompareAndSwap(context.Background(), b.Expected, staleNext, b.Transaction); !errors.Is(err, recovery.ErrConflict) {
			t.Fatalf("stale CAS accepted: %v", err)
		}
		if a.state != b.Next {
			t.Fatalf("stale CAS changed anchor: %+v", a.state)
		}
	})
}
