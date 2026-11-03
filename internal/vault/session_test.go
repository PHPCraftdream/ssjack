package vault

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func sessionTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestSessionSerializesAndCoalescesOwnedSnapshots(t *testing.T) {
	state, server := directoryFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	persisted := make(chan string, 4)
	var calls, released atomic.Int32
	var payloads [][]byte
	s := newSession(state, func(ctx context.Context, payload []byte) error {
		v, err := unmarshal(payload)
		if err != nil {
			return err
		}
		defer v.Close()
		name := v.Servers[server].Name
		payloads = append(payloads, payload)
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
			}
		}
		persisted <- name
		return nil
	}, func() { released.Add(1) })
	t.Cleanup(s.Discard)
	if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, "first") }); err != nil {
		t.Fatal(err)
	}
	ctx := sessionTestContext(t)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("save worker did not start")
	}
	for _, name := range []string{"second", "third"} {
		if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, name) }); err != nil {
			t.Fatal(err)
		}
	}
	status := s.Status()
	if !status.Pending || status.Revision != 3 || status.SavedRevision != 0 {
		t.Fatal("pending revisions were reported as saved")
	}
	close(release)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || <-persisted != "first" || <-persisted != "third" {
		t.Fatal("save worker reordered snapshots or retained an obsolete queued revision")
	}
	for _, payload := range payloads {
		if !bytes.Equal(payload, make([]byte, len(payload))) {
			t.Fatal("completed plaintext snapshot was not cleared")
		}
	}
	if status := s.Status(); status.Pending || status.Revision != 3 || status.SavedRevision != 3 {
		t.Fatal("latest completed revision was not reported as saved")
	}
	if err := s.Close(ctx); err != nil || released.Load() != 1 {
		t.Fatal("session did not join the worker before releasing its unlock context")
	}
	if err := s.Apply(func(*Vault) error { return nil }); err == nil {
		t.Fatal("closed session accepted an edit")
	}
}

func TestSessionFailedFormsNeverQueueWrites(t *testing.T) {
	state, server := directoryFixture(t)
	var calls atomic.Int32
	s := newSession(state, func(context.Context, []byte) error { calls.Add(1); return nil }, func() {})
	t.Cleanup(s.Discard)
	cancelled := errors.New("form cancelled")
	if err := s.Apply(func(v *Vault) error {
		if err := v.RenameServer(server, "not-committed"); err != nil {
			return err
		}
		return cancelled
	}); !errors.Is(err, cancelled) {
		t.Fatal("cancelled form did not report cancellation")
	}
	if err := s.Apply(func(v *Vault) error { v.Version = 99; return nil }); err == nil {
		t.Fatal("invalid form was accepted")
	}
	if err := s.Flush(sessionTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if status := s.Status(); status.Revision != 0 || status.Pending || calls.Load() != 0 {
		t.Fatal("cancelled or invalid form changed state or saved a snapshot")
	}
	if state.Servers[server].Name != "production" {
		t.Fatal("failed candidate mutated the original in-memory state")
	}
}

func TestSessionSaveFailureKeepsChangesUntilExplicitRetry(t *testing.T) {
	state, server := directoryFixture(t)
	failure := errors.New("synthetic persistence failure")
	var calls, released atomic.Int32
	persisted := make(chan string, 1)
	s := newSession(state, func(_ context.Context, payload []byte) error {
		if calls.Add(1) == 1 {
			return failure
		}
		v, err := unmarshal(payload)
		if err != nil {
			return err
		}
		defer v.Close()
		persisted <- v.Servers[server].Name
		return nil
	}, func() { released.Add(1) })
	t.Cleanup(s.Discard)
	ctx := sessionTestContext(t)
	if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, "first") }); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); !errors.Is(err, failure) {
		t.Fatal("save failure was hidden")
	}
	if err := s.Close(ctx); !errors.Is(err, failure) || released.Load() != 0 {
		t.Fatal("failed close discarded unsaved state or released its key")
	}
	if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, "latest") }); err != nil {
		t.Fatal("session stopped accepting owner edits after save failure")
	}
	if status := s.Status(); !status.Pending || status.Revision != 2 || !errors.Is(status.Err, failure) {
		t.Fatal("failed pending state was not retained")
	}
	if err := s.Retry(); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if <-persisted != "latest" || calls.Load() != 2 {
		t.Fatal("explicit retry did not save the latest owner state")
	}
	if err := s.Close(ctx); err != nil || released.Load() != 1 {
		t.Fatal("recovered session did not close cleanly")
	}
}

func TestSessionCloseTimeoutDoesNotDiscardPendingState(t *testing.T) {
	state, server := directoryFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var released atomic.Int32
	s := newSession(state, func(ctx context.Context, _ []byte) error {
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func() { released.Add(1) })
	t.Cleanup(s.Discard)
	if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, "pending") }); err != nil {
		t.Fatal(err)
	}
	ctx := sessionTestContext(t)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("save worker did not start")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Close(cancelled); !errors.Is(err, context.Canceled) || released.Load() != 0 {
		t.Fatal("close timeout lost pending data or the unlock context")
	}
	close(release)
	if err := s.Close(ctx); err != nil || released.Load() != 1 {
		t.Fatal("pending save could not finish after close timeout")
	}
}
