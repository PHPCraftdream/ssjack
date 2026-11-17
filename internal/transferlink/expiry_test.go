package transferlink

import (
	"reflect"
	"testing"
	"time"
)

// longWindow keeps the drop window out of the way: these tests are about the
// idle expiry only.
const longWindow = 1000 * time.Hour

// knownProfile returns a profile that has learned a speed, a setup time, a drop
// and a chunk size, in chunked mode, and has seen three attempts without
// progress.
func knownProfile(c *fakeClock) *Profile {
	p := NewProfile(Config{Now: c.Now, Window: longWindow})
	p.StreamProgress(mb, time.Second)
	p.ConnectionSetup(200 * time.Millisecond)
	p.Dropped(mb, 5*time.Second, FailLink)
	p.ForceChunked(2 * mb)
	for i := 0; i < 3; i++ {
		p.Dropped(0, time.Second, FailSetup)
	}
	return p
}

func requireKnown(t *testing.T, p *Profile) {
	t.Helper()
	s := p.Snapshot()
	if s.Speed <= 0 || s.Setup <= 0 || !s.SurviveKnown || s.Drops == 0 || s.Stored == 0 || s.Mode != ModeChunked || s.Stalled == 0 {
		t.Fatalf("profile lost what it learned: %+v", s)
	}
}

func requireUnknown(t *testing.T, p *Profile) {
	t.Helper()
	fresh := NewProfile(Config{Now: newClock().Now, Window: longWindow})
	if got, want := p.Snapshot(), fresh.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("profile is not reset to unknown:\n got %+v\nwant %+v", got, want)
	}
	if p.GiveUp() {
		t.Fatal("a reset profile still gives up")
	}
}

func TestIdleProfileIsDiscardedAtTheLimit(t *testing.T) {
	c := newClock()
	p := knownProfile(c)
	requireKnown(t, p)

	c.Advance(DefaultIdleExpiry - time.Nanosecond)
	requireKnown(t, p)
	c.Advance(time.Nanosecond)
	requireUnknown(t, p)
}

func TestDecisionAfterExpiryStartsFromUnknown(t *testing.T) {
	c := newClock()
	p := NewProfile(Config{Now: c.Now, Window: longWindow})
	p.StreamProgress(mb, time.Second)
	p.Dropped(mb, time.Second, FailLink)
	const size = 100 * mb
	if step := p.Decide(size); step.Mode != ModeChunked {
		t.Fatalf("a known lossy link decided %+v, want chunked", step)
	}

	c.Advance(DefaultIdleExpiry)
	if step := p.Decide(size); step.Mode != ModeStream || step.Len != size {
		t.Fatalf("after the expiry Decide = %+v, want a whole stream", step)
	}
	if p.UseChunks(size) {
		t.Fatal("an expired profile still asks for chunks")
	}
	if p.Mode() != ModeStream {
		t.Fatal("an expired profile is still in chunked mode")
	}
}

func TestEveryUseRestartsTheIdleTime(t *testing.T) {
	uses := map[string]func(p *Profile){
		"StreamProgress":  func(p *Profile) { p.StreamProgress(mb, time.Second) },
		"ChunkDone":       func(p *Profile) { p.ChunkDone(mb, time.Second) },
		"ConnectionSetup": func(p *Profile) { p.ConnectionSetup(time.Second) },
		"Dropped":         func(p *Profile) { p.Dropped(mb, time.Second, FailLink) },
		"Dropped setup":   func(p *Profile) { p.Dropped(0, time.Second, FailSetup) },
		"ForceChunked":    func(p *Profile) { p.ForceChunked(mb) },
		"GiveUp":          func(p *Profile) { p.GiveUp() },
		"UseChunks":       func(p *Profile) { p.UseChunks(mb) },
		"NextChunk":       func(p *Profile) { p.NextChunk(mb) },
		"Decide":          func(p *Profile) { p.Decide(100 * mb) },
	}
	for name, use := range uses {
		t.Run(name, func(t *testing.T) {
			c := newClock()
			p := knownProfile(c)
			c.Advance(40 * time.Minute)
			use(p)
			c.Advance(40 * time.Minute)
			// 80 minutes since the profile was built, 40 since the use.
			if s := p.Snapshot(); s.Speed <= 0 || !s.SurviveKnown {
				t.Fatalf("a profile used 40 minutes ago was discarded: %+v", s)
			}
		})
	}
}

func TestSnapshotAndModeDoNotCountAsUse(t *testing.T) {
	c := newClock()
	p := knownProfile(c)
	c.Advance(40 * time.Minute)
	_ = p.Snapshot()
	_ = p.Mode()
	c.Advance(40 * time.Minute)
	requireUnknown(t, p)
}

func TestSnapshotAndModeShowAStaleProfileReset(t *testing.T) {
	c := newClock()
	p := knownProfile(c)
	c.Advance(2 * DefaultIdleExpiry)
	if p.Mode() != ModeStream {
		t.Fatal("Mode shows the stale chunked mode")
	}
	if s := p.Snapshot(); s.Speed != 0 || s.Drops != 0 || s.Stored != 0 {
		t.Fatalf("Snapshot shows stale knowledge: %+v", s)
	}
}

func TestGiveUpDoesNotSurviveTheExpiry(t *testing.T) {
	c := newClock()
	p := NewProfile(Config{Now: c.Now, Window: longWindow})
	for i := 0; i < MaxNoProgress; i++ {
		p.Dropped(0, time.Second, FailSetup)
	}
	if !p.GiveUp() {
		t.Fatal("eight attempts without progress did not give up")
	}
	c.Advance(DefaultIdleExpiry)
	if p.GiveUp() {
		t.Fatal("a stale no-progress count made a new transfer give up at once")
	}
}

func TestOutcomeReportsNeverDiscardTheStateOfTheirOwnJob(t *testing.T) {
	// One attempt may run longer than the idle limit (a big stream on a slow
	// link). The decision that started it counted as use; the reports that end
	// it only refresh, so the job keeps its counters.
	c := newClock()
	p := NewProfile(Config{Now: c.Now, Window: longWindow})
	p.StreamProgress(mb, time.Second)
	p.Dropped(mb, time.Second, FailLink)
	p.ForceChunked(2 * mb)
	if step := p.Decide(100 * mb); step.Mode != ModeChunked {
		t.Fatalf("Decide = %+v", step)
	}
	p.Dropped(0, time.Second, FailSetup)
	p.Dropped(0, time.Second, FailSetup)
	before := p.Snapshot().Stalled

	c.Advance(3 * DefaultIdleExpiry)
	p.StreamProgress(mb, time.Second)
	p.Dropped(0, time.Second, FailSetup)
	s := p.Snapshot()
	if s.Stalled != before+1 || s.Mode != ModeChunked || s.Drops == 0 {
		t.Fatalf("a long attempt lost its job's state: %+v (stalled before %d)", s, before)
	}
}

func TestExpiredProfileLearnsAgainAndExpiresAgain(t *testing.T) {
	c := newClock()
	p := knownProfile(c)
	c.Advance(DefaultIdleExpiry)
	requireUnknown(t, p)

	p.StreamProgress(mb, time.Second)
	if s := p.Snapshot(); s.Speed <= 0 || s.Drops != 0 || s.Mode != ModeStream {
		t.Fatalf("a new sample after the expiry started from stale state: %+v", s)
	}
	c.Advance(DefaultIdleExpiry - time.Nanosecond)
	if s := p.Snapshot(); s.Speed <= 0 {
		t.Fatalf("the idle time did not restart at the new sample: %+v", s)
	}
	c.Advance(time.Nanosecond)
	requireUnknown(t, p)
}

func TestIdleExpiryIsConfigurable(t *testing.T) {
	c := newClock()
	p := NewProfile(Config{Now: c.Now, Window: longWindow, IdleExpiry: 10 * time.Minute})
	p.StreamProgress(mb, time.Second)
	c.Advance(10*time.Minute - time.Nanosecond)
	if p.Snapshot().Speed <= 0 {
		t.Fatal("expired before the configured limit")
	}
	c.Advance(time.Nanosecond)
	if p.Snapshot().Speed != 0 {
		t.Fatal("not expired at the configured limit")
	}
	// A non-positive setting means the default.
	d := NewProfile(Config{Now: c.Now, IdleExpiry: -time.Second})
	d.StreamProgress(mb, time.Second)
	c.Advance(DefaultIdleExpiry - time.Nanosecond)
	if d.Snapshot().Speed <= 0 {
		t.Fatal("a negative setting did not fall back to the default")
	}
}

func TestADefaultProfileExpiresAfterAnHour(t *testing.T) {
	if DefaultIdleExpiry != time.Hour {
		t.Fatalf("DefaultIdleExpiry = %s, the spec says one hour", DefaultIdleExpiry)
	}
}
