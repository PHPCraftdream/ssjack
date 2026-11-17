package faultproxy

import "time"

const nsPerSecond = int64(time.Second)

// bucket is an integer token bucket: rate bytes per second, capacity burst,
// starting full. The sub-byte remainder of every refill is carried, so the
// long-run rate is exact. It is owned by one goroutine and needs no lock.
type bucket struct {
	rate   int64
	burst  int64
	tokens int64
	acc    int64 // refill remainder, in byte*nanosecond units, < nsPerSecond
	last   time.Time
}

func newBucket(rate, burst int64, now time.Time) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst, last: now}
}

// refill credits the time elapsed since the last refill.
func (b *bucket) refill(now time.Time) {
	elapsed := now.Sub(b.last)
	if elapsed <= 0 {
		return
	}
	b.last = now
	// Beyond this the bucket is full for sure; the guard also keeps
	// elapsed*rate inside int64 (burst and rate are capped at maxBurst).
	if int64(elapsed) > b.burst*nsPerSecond/b.rate {
		b.tokens, b.acc = b.burst, 0
		return
	}
	total := b.acc + int64(elapsed)*b.rate
	b.tokens += total / nsPerSecond
	b.acc = total % nsPerSecond
	if b.tokens >= b.burst {
		b.tokens, b.acc = b.burst, 0
	}
}

// try spends n tokens (n <= burst) and returns 0, or leaves the bucket
// unchanged and returns how long to wait until n tokens are available.
func (b *bucket) try(now time.Time, n int64) time.Duration {
	b.refill(now)
	if b.tokens >= n {
		b.tokens -= n
		return 0
	}
	need := (n-b.tokens)*nsPerSecond - b.acc
	wait := (need + b.rate - 1) / b.rate
	if wait < 1 {
		wait = 1
	}
	return time.Duration(wait)
}
