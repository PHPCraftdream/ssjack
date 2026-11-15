package ownerdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func rotatingManager() *Manager {
	done := make(chan struct{})
	close(done)
	lifetime, cancel := context.WithCancel(context.Background())
	return &Manager{busy: true, rotating: true, jobs: make(chan string, 1), changed: make(chan struct{}), done: done, ctx: lifetime, cancel: cancel}
}

func TestRotationInFlightExcludesWritersWithoutHoldingTheLock(t *testing.T) {
	m := rotatingManager()
	// m.mu is free: a reader or a refused writer returns at once.
	if !m.mu.TryLock() {
		t.Fatal("an in-flight rotation held the manager lock")
	}
	m.mu.Unlock()
	if err := m.Edit(func(*vault.Vault) error { return nil }); !errors.Is(err, ErrPending) {
		t.Fatalf("edit during rotation = %v", err)
	}
	if err := m.RetryDatabaseAt(1); !errors.Is(err, ErrPending) {
		t.Fatalf("retry during rotation = %v", err)
	}
	if err := m.beginRotation(true); !errors.Is(err, ErrPending) {
		t.Fatalf("second rotation operation = %v", err)
	}
	if !m.busy || !m.rotating {
		t.Fatal("a refused operation cleared the in-flight rotation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close during rotation = %v", err)
	}
	if m.closing || m.closed {
		t.Fatal("a timed-out close left the manager closing")
	}
}

func TestDiscardWaitsForRotationToEnd(t *testing.T) {
	m := rotatingManager()
	stopped := make(chan struct{})
	go func() {
		m.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("stop did not wait for the in-flight rotation")
	case <-time.After(100 * time.Millisecond):
	}
	if m.ctx.Err() != nil {
		t.Fatal("stop cancelled the manager before the rotation ended")
	}
	m.endRotation()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not resume after the rotation ended")
	}
	if !m.closed || m.busy || m.rotating || m.ctx.Err() == nil {
		t.Fatal("stop after rotation left the manager open")
	}
}
