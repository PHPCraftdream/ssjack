package confirm

import (
	"testing"
	"time"
)

// stepClock is a manual clock for the store tests.
type stepClock struct{ at time.Time }

func (c *stepClock) Now() time.Time { return c.at }

// constantReader yields the same byte forever, so the nonces are
// deterministic.
type constantReader struct{ b byte }

func (r constantReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// counterReader produces DISTINCT deterministic nonces: each read fills the
// nonce bytes with a little-endian counter, so consecutive nonces never
// collide and the cap tests mint distinct tokens.
type counterReader struct{ n uint16 }

func (r *counterReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	p[0] = byte(r.n)
	p[1] = byte(r.n >> 8)
	r.n++
	return len(p), nil
}

func TestCreateTokensAreDeterministicAndBounded(t *testing.T) {
	clock := &stepClock{at: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	first := NewManager(clock.Now, constantReader{b: 7})
	second := NewManager(clock.Now, constantReader{b: 7})
	tokenA, ok := first.create("remote_upload", "d", KindTransfer, "s1")
	if !ok {
		t.Fatal("create failed")
	}
	tokenB, ok := second.create("remote_upload", "d", KindTransfer, "s1")
	if !ok {
		t.Fatal("create failed")
	}
	if tokenA != tokenB {
		t.Fatalf("the same rand produced %q and %q", tokenA, tokenB)
	}
	if len(tokenA) == 0 || len(tokenA) > stateLimit {
		t.Fatalf("token of length %d breaks the 1 KiB cap", len(tokenA))
	}
	different := NewManager(clock.Now, constantReader{b: 8})
	tokenC, _ := different.create("remote_upload", "d", KindTransfer, "s1")
	if tokenC == tokenA {
		t.Fatal("a different rand reproduced the same token")
	}
}

func TestExpiryMovesToTombstoneAndThenForgets(t *testing.T) {
	clock := &stepClock{at: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	m := NewManager(clock.Now, constantReader{b: 1})
	token, ok := m.create("remote_upload", "d", KindTransfer, "s1")
	if !ok {
		t.Fatal("create failed")
	}
	clock.at = clock.at.Add(activeTTL - time.Second)
	if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeAccepted {
		t.Fatalf("a call one second before expiry answered %v", got)
	}
	t.Run("expired within the window", func(t *testing.T) {
		token, _ := m.create("remote_upload", "d", KindTransfer, "s1")
		clock.at = clock.at.Add(activeTTL + time.Second)
		if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeTimedOut {
			t.Fatalf("an expired state answered %v, want timed out", got)
		}
		if len(m.tombstones) != 1 {
			t.Fatalf("%d tombstones, want one", len(m.tombstones))
		}
		if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeTimedOut {
			t.Fatalf("a tombstoned retry answered %v, want timed out", got)
		}
	})
	t.Run("expired tombstone foreign session", func(t *testing.T) {
		// Tombstones carry session identity: an expired-but-retained token
		// retried by a foreign session is generic, the originating session is
		// told the confirmation timed out, and past the window even the
		// foreign session cannot resurrect anything.
		token, ok := m.create("remote_upload", "d", KindTransfer, "s1")
		if !ok {
			t.Fatal("create failed")
		}
		clock.at = clock.at.Add(activeTTL + time.Second)
		// Move the expired entry into the tombstone map first (the sweep runs
		// on every create); only then does the session-identity branch decide
		// between generic invalid and timed out.
		if _, ok := m.create("remote_upload", "d", KindTransfer, "s1"); !ok {
			t.Fatal("the sweeping create failed")
		}
		if got := m.validate(token, "remote_upload", "d", "accept", "s2"); got != outcomeInvalid {
			t.Fatalf("a foreign session answered %v, want invalid", got)
		}
		if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeTimedOut {
			t.Fatalf("the originating session answered %v, want timed out", got)
		}
		clock.at = clock.at.Add(tombstoneTTL)
		if got := m.validate(token, "remote_upload", "d", "accept", "s2"); got != outcomeInvalid {
			t.Fatalf("a past-window foreign retry answered %v, want invalid", got)
		}
	})
	t.Run("evicted past the window", func(t *testing.T) {
		clock.at = clock.at.Add(tombstoneTTL)
		if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeInvalid {
			t.Fatalf("a forgotten state answered %v, want invalid", got)
		}
	})
}

func TestTombstoneCapEvictsOldestFirst(t *testing.T) {
	clock := &stepClock{at: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	m := NewManager(clock.Now, &counterReader{})
	tokens := make([]string, tombstoneCap)
	for i := range tokens {
		token, ok := m.create("remote_upload", "d", KindTransfer, "s1")
		if !ok {
			t.Fatalf("create %d failed", i)
		}
		tokens[i] = token
		clock.at = clock.at.Add(time.Second)
	}
	// All tokens must be distinct: with the old constant-byte reader every
	// create minted the SAME nonce, so all tokens collapsed onto one map key
	// and the cap assertions below were vacuous.
	distinct := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		distinct[token] = true
	}
	if len(distinct) != tombstoneCap {
		t.Fatalf("%d distinct tokens were minted, want %d", len(distinct), tombstoneCap)
	}
	clock.at = clock.at.Add(activeTTL)
	for i, token := range tokens {
		if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeTimedOut {
			t.Fatalf("token %d answered %v, want timed out", i, got)
		}
	}
	if len(m.tombstones) != tombstoneCap {
		t.Fatalf("%d tombstones, want %d", len(m.tombstones), tombstoneCap)
	}
	extra, ok := m.create("remote_upload", "d", KindTransfer, "s1")
	if !ok {
		t.Fatal("create failed")
	}
	clock.at = clock.at.Add(activeTTL + time.Second)
	if got := m.validate(extra, "remote_upload", "d", "accept", "s1"); got != outcomeTimedOut {
		t.Fatalf("the overflowing state answered %v, want timed out", got)
	}
	if len(m.tombstones) != tombstoneCap {
		t.Fatalf("%d tombstones after the eviction, want %d", len(m.tombstones), tombstoneCap)
	}
	if _, kept := m.tombstones[tokens[0]]; kept {
		t.Fatal("the oldest tombstone survived the eviction")
	}
	if _, kept := m.tombstones[tokens[1]]; !kept {
		t.Fatal("the second-oldest tombstone was evicted first")
	}
}

func TestPendingCapFailsClosed(t *testing.T) {
	// Counter nonces: the old constant-byte reader yielded only identical
	// zero nonces, so all creations collided on one token and the cap was
	// never actually reached.
	m := NewManager(func() time.Time { return time.Unix(0, 0) }, &counterReader{})
	minted := make(map[string]bool, pendingCap)
	for i := 0; i < pendingCap; i++ {
		token, ok := m.create("remote_upload", "d", KindTransfer, "s1")
		if !ok {
			t.Fatalf("create %d failed below the cap", i)
		}
		minted[token] = true
	}
	if len(minted) != pendingCap {
		t.Fatalf("%d distinct tokens were minted below the cap, want %d", len(minted), pendingCap)
	}
	if _, ok := m.create("remote_upload", "d", KindTransfer, "s1"); ok {
		t.Fatal("a state was minted beyond the pending cap")
	}
}

func TestCreateReclaimsExpiredPendingEntries(t *testing.T) {
	clock := &stepClock{at: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	var nonce uint16
	random := readerFunc(func(p []byte) (int, error) {
		for i := range p {
			p[i] = 0
		}
		p[0] = byte(nonce)
		p[1] = byte(nonce >> 8)
		nonce++
		return len(p), nil
	})
	m := NewManager(clock.Now, random)
	tokens := make([]string, pendingCap)
	for i := range tokens {
		token, ok := m.create("remote_upload", "d", KindTransfer, "s1")
		if !ok {
			t.Fatalf("create %d failed below the cap", i)
		}
		tokens[i] = token
	}
	clock.at = clock.at.Add(activeTTL + time.Second)
	if _, ok := m.create("remote_upload", "d", KindTransfer, "s1"); !ok {
		t.Fatal("create failed after expired entries should have been reclaimed")
	}
	for i, token := range tokens {
		if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeTimedOut {
			t.Fatalf("swept token %d answered %v, want timed out", i, got)
		}
	}
	clock.at = clock.at.Add(tombstoneTTL)
	for i, token := range tokens {
		if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeInvalid {
			t.Fatalf("swept token %d answered %v after the tombstone window, want invalid", i, got)
		}
	}
}

type readerFunc func([]byte) (int, error)

func (r readerFunc) Read(p []byte) (int, error) { return r(p) }

func TestValidateRejectsWrongToolDigestAndAction(t *testing.T) {
	clock := &stepClock{at: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	m := NewManager(clock.Now, constantReader{b: 3})
	token, _ := m.create("remote_upload", "d", KindTransfer, "s1")
	if got := m.validate(token, "remote_download", "d", "accept", "s1"); got != outcomeInvalid {
		t.Fatalf("a wrong tool answered %v", got)
	}
	if got := m.validate(token, "remote_upload", "other", "accept", "s1"); got != outcomeInvalid {
		t.Fatalf("a wrong digest answered %v", got)
	}
	if got := m.validate(token, "remote_upload", "d", "maybe", "s1"); got != outcomeInvalid {
		t.Fatalf("an invalid action answered %v", got)
	}
	// A wrong session is refused with the generic error and the record is NOT
	// consumed: the rightful session must still be able to answer it.
	if got := m.validate(token, "remote_upload", "d", "accept", "s2"); got != outcomeInvalid {
		t.Fatalf("a foreign session answered %v, want invalid", got)
	}
	if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeAccepted {
		t.Fatalf("the state did not survive the failed validations: %v", got)
	}
	if got := m.validate(token, "remote_upload", "d", "accept", "s1"); got != outcomeInvalid {
		t.Fatalf("a replayed state answered %v, want invalid", got)
	}
}

func TestDialogMessageIsFixed(t *testing.T) {
	var dialog DialogBuilder = fixedDialog{}
	if got := dialog.ReviewMessage(KindTransfer); got != reviewMessage {
		t.Fatalf("the dialog answered %q, want %q", got, reviewMessage)
	}
}
