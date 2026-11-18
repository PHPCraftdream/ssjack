package pace

import (
	"testing"
	"time"
)

// maxBurst mirrors the proxy rate cap that keeps the arithmetic inside int64.
const maxBurst = int64(1) << 32

func TestBucketStartsFullAndReportsTheWait(t *testing.T) {
	t0 := time.Date(2030, time.March, 1, 0, 0, 0, 0, time.UTC)
	b := NewBucket(1000, 1000, t0)
	if wait := b.Try(t0, 1000); wait != 0 {
		t.Fatalf("a full bucket asked to wait %s", wait)
	}
	if wait := b.Try(t0, 1); wait != time.Millisecond {
		t.Fatalf("one byte at 1000 B/s should wait 1ms, got %s", wait)
	}
	if wait := b.Try(t0.Add(time.Millisecond/2), 1); wait != time.Millisecond/2 {
		t.Fatalf("half a millisecond later the wait should be 0.5ms, got %s", wait)
	}
	if wait := b.Try(t0.Add(time.Millisecond), 1); wait != 0 {
		t.Fatalf("the byte should be available after 1ms, got a wait of %s", wait)
	}
}

func TestBucketCarriesTheSubByteRemainder(t *testing.T) {
	t0 := time.Date(2030, time.March, 1, 0, 0, 0, 0, time.UTC)
	b := NewBucket(3, 3, t0)
	if wait := b.Try(t0, 3); wait != 0 {
		t.Fatal("a full bucket refused its own capacity")
	}
	// 3 B/s: 333ms is 0.999 bytes, 334ms is 1.002 bytes.
	now := t0
	for step := 1; step <= 333; step++ {
		now = now.Add(time.Millisecond)
		b.refill(now)
	}
	if b.tokens != 0 {
		t.Fatalf("tokens after 333ms = %d, want 0", b.tokens)
	}
	now = now.Add(time.Millisecond)
	b.refill(now)
	if b.tokens != 1 {
		t.Fatalf("tokens after 334ms = %d, want 1", b.tokens)
	}
	for step := 335; step <= 1000; step++ {
		now = now.Add(time.Millisecond)
		b.refill(now)
	}
	if b.tokens != 3 {
		t.Fatalf("tokens after a full second = %d, want the capacity 3", b.tokens)
	}
}

func TestBucketNeverExceedsItsCapacityOrOverflows(t *testing.T) {
	t0 := time.Date(2030, time.March, 1, 0, 0, 0, 0, time.UTC)
	b := NewBucket(maxBurst, maxBurst, t0)
	b.tokens = 0
	b.refill(t0.Add(1000 * time.Hour))
	if b.tokens != maxBurst {
		t.Fatalf("tokens after a long idle period = %d, want %d", b.tokens, maxBurst)
	}
	slow := NewBucket(1, 1, t0)
	slow.tokens = 0
	slow.refill(t0.Add(500 * time.Millisecond))
	if slow.tokens != 0 {
		t.Fatal("half a second at 1 B/s must not create a byte")
	}
	// A clock that stands still or goes backwards changes nothing.
	slow.refill(t0)
	if slow.tokens != 0 || !slow.last.Equal(t0.Add(500*time.Millisecond)) {
		t.Fatal("a backwards clock changed the bucket")
	}
}
