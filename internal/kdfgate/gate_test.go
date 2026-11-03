package kdfgate_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/kdfgate"
)

func TestSingleLeaseAndOldDoubleRelease(t *testing.T) {
	a, ok := kdfgate.TryAcquire()
	if !ok {
		t.Fatal("initial admission unavailable")
	}
	defer a()
	if release, ok := kdfgate.TryAcquire(); ok {
		release()
		t.Fatal("second batch admitted")
	}
	a()
	b, ok := kdfgate.TryAcquire()
	if !ok {
		t.Fatal("first release did not return admission")
	}
	defer b()
	a()
	if release, ok := kdfgate.TryAcquire(); ok {
		release()
		t.Fatal("old release freed a new owner's lease")
	}
	b()
	c, ok := kdfgate.TryAcquire()
	if !ok {
		t.Fatal("new owner could not release")
	}
	c()
}

func TestCancellationDoesNotRevokeOwnedWork(t *testing.T) {
	release, err := kdfgate.Acquire(nil)
	if !errors.Is(err, kdfgate.ErrInvalidContext) || release != nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release, err = kdfgate.Acquire(ctx)
	if !errors.Is(err, context.Canceled) || release != nil {
		t.Fatal("already cancelled context admitted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	owned, err := kdfgate.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer owned()
	cancel()
	if next, ok := kdfgate.TryAcquire(); ok {
		next()
		t.Fatal("cancellation revoked a still-running batch")
	}
	owned()
	next, ok := kdfgate.TryAcquire()
	if !ok {
		t.Fatal("explicit release lost admission")
	}
	next()
}

type result struct {
	release func()
	err     error
}

func wait(t *testing.T, done <-chan result) result {
	t.Helper()
	select {
	case value := <-done:
		return value
	case <-time.After(30 * time.Second):
		t.Fatal("admission did not finish")
		return result{}
	}
}

func TestWaitingCancellationAndSubsequentAcquire(t *testing.T) {
	owned, ok := kdfgate.TryAcquire()
	if !ok {
		t.Fatal("initial lease unavailable")
	}
	defer owned()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan result, 1)
	go func() { release, err := kdfgate.Acquire(ctx); done <- result{release, err} }()
	cancel()
	value := wait(t, done)
	if !errors.Is(value.err, context.Canceled) || value.release != nil {
		t.Fatal("waiting cancellation retained a lease")
	}
	if release, ok := kdfgate.TryAcquire(); ok {
		release()
		t.Fatal("cancelling waiter freed another batch")
	}
	go func() { release, err := kdfgate.Acquire(context.Background()); done <- result{release, err} }()
	owned()
	value = wait(t, done)
	if value.err != nil || value.release == nil {
		t.Fatalf("waiting acquire: %v", value.err)
	}
	value.release()
}

func TestConcurrentReleaseIsIdempotent(t *testing.T) {
	release, ok := kdfgate.TryAcquire()
	if !ok {
		t.Fatal("initial lease unavailable")
	}
	defer release()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); release() }()
	}
	workers.Wait()
	next, ok := kdfgate.TryAcquire()
	if !ok {
		t.Fatal("concurrent releases lost the permit")
	}
	defer next()
	release()
	if other, ok := kdfgate.TryAcquire(); ok {
		other()
		t.Fatal("late concurrent release freed next owner")
	}
}
