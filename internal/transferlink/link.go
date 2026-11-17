// Package transferlink holds the pure decision logic of the chunked,
// resumable transfer mode (docs/FILE-TRANSFER.md): a per-target link Profile
// that learns throughput, setup cost and connection lifetime from events, and
// the planner helpers (plan.go) that cut the missing byte ranges into chunks.
//
// The package performs no I/O, never starts a timer and never reads the wall
// clock on its own: the caller injects a clock (Config.Now) and reports
// durations explicitly. Same event sequence, same decisions.
//
// Driving loop (upload or download):
//
//	p := transferlink.NewProfile(transferlink.Config{Now: clock})
//	for remaining > 0 {
//		if p.GiveUp() { /* fail the job with class link_unstable */ }
//		step := p.Decide(remaining)
//		chunk := step.Len
//		if step.Mode == transferlink.ModeStream { chunk = 0 } // whole gap
//		rg, ok, _ := transferlink.NextRange(size, covered, chunk)
//		// connect: p.ConnectionSetup(d); send rg; feed p.StreamProgress as
//		// bytes flow; on success p.ChunkDone (chunked) and extend covered;
//		// on a connection loss p.Dropped(sent, connLifetime, FailLink).
//	}
//	p.Succeeded()
package transferlink

import (
	"math"
	"sync"
	"time"
)

const (
	// MinChunk is the smallest chunk the planner emits (except for the tail).
	MinChunk int64 = 256 << 10
	// MaxChunk is the largest chunk the planner emits.
	MaxChunk int64 = 64 << 20

	// MaxNoProgress is the number of consecutive attempts without progress
	// after which GiveUp reports true.
	MaxNoProgress = 8
	// GrowAfter is the number of consecutive completed chunks that grows
	// the stored chunk size by 1.5 (capped at MaxChunk).
	GrowAfter = 4
	// SafetyFactor scales the survivability bound: S <= B*T_survive*SafetyFactor.
	SafetyFactor = 0.5
	// OverheadFactor sets the setup-overhead floor: S >= B*OverheadFactor*t_setup
	// (connection setup stays below about 5% of the chunk time).
	OverheadFactor = 20.0
	// ImproveFactor is the speed gain over the speed at the last drop that
	// lets a chunked transfer return to a single stream.
	ImproveFactor = 2.0

	// DefaultWindow is how long a drop stays in the profile.
	DefaultWindow = 5 * time.Minute

	maxDrops  = 8   // bounded history of recent drops
	ewmaAlpha = 0.3 // weight of a new sample
	maxSpeed  = 1e15
)

// Mode is the transfer mode a Profile currently recommends.
type Mode int

const (
	// ModeStream sends everything still missing in one stream.
	ModeStream Mode = iota
	// ModeChunked sends bounded chunks, each on its own connection.
	ModeChunked
)

// String implements fmt.Stringer.
func (m Mode) String() string {
	if m == ModeChunked {
		return "chunked"
	}
	return "stream"
}

// FailureKind classifies why an attempt ended. Only FailLink and FailSetup
// are link failures and change the profile; every other kind (including the
// zero value and unknown values) is ignored by Dropped.
type FailureKind int

const (
	// FailUnknown is the zero value: not a link failure, ignored.
	FailUnknown FailureKind = iota
	// FailLink is an established connection that was lost mid-transfer.
	FailLink
	// FailSetup is a connection that could not be established.
	FailSetup
	// FailCancelled is a cancellation by the caller or the owner.
	FailCancelled
	// FailRefused is a refused path or policy failure.
	FailRefused
	// FailIntegrity is a digest or size mismatch.
	FailIntegrity
	// FailLimit is a transfer limit failure.
	FailLimit
)

// Config configures NewProfile.
type Config struct {
	// Now is the injected clock. Nil means time.Now (the only place the
	// package refers to the wall clock).
	Now func() time.Time
	// Window is how long a drop is remembered; zero means DefaultWindow.
	Window time.Duration
}

// Step is the decision for the next attempt.
type Step struct {
	// Mode is the mode of the attempt.
	Mode Mode
	// Len is the number of bytes to send: the whole remainder in stream
	// mode, the chunk size (1..remaining-1, at least MinChunk) in chunked
	// mode, 0 when nothing remains.
	Len int64
}

// Snapshot is a read-only copy of the profile state for logs and tests.
type Snapshot struct {
	Mode         Mode
	Speed        float64       // throughput EWMA, bytes/s, 0 = unknown
	Setup        time.Duration // setup EWMA, 0 = unknown
	Survive      time.Duration // min lifetime over the drop window
	SurviveKnown bool
	Chunk        int64 // effective chunk size now (before the remaining clamp)
	Stored       int64 // stored AIMD size, 0 = not seeded yet
	OKStreak     int   // consecutive completed chunks
	Stalled      int   // consecutive attempts without progress
	Drops        int   // drops inside the window
	DropSpeed    float64
}

type drop struct {
	at   time.Time
	life time.Duration
}

// Profile is the per-target link knowledge. RAM only; safe for concurrent use.
type Profile struct {
	mu     sync.Mutex
	now    func() time.Time
	window time.Duration

	speed      float64 // bytes/s, 0 = unknown
	setup      float64 // seconds, 0 = unknown
	drops      []drop  // at most maxDrops, oldest first
	dropSpeed  float64 // speed at the last drop, 0 = unknown
	chunk      int64   // stored AIMD chunk size, 0 = not seeded
	mode       Mode
	okStreak   int
	stalled    int
	bestStream int64 // largest byte count of a dropped stream attempt
}

// NewProfile returns an empty profile in stream mode.
func NewProfile(cfg Config) *Profile {
	p := &Profile{now: cfg.Now, window: cfg.Window}
	if p.now == nil {
		p.now = time.Now
	}
	if p.window <= 0 {
		p.window = DefaultWindow
	}
	return p
}

// StreamProgress feeds one throughput sample: bytes moved in elapsed data
// time (excluding connection setup). Use it while a stream (or the partial
// data of a chunk that was cut off) flows. Non-positive input is ignored.
func (p *Profile) StreamProgress(bytes int64, elapsed time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observeLocked(bytes, elapsed)
}

// ChunkDone reports a completed chunk: it feeds throughput, counts as
// progress and drives the additive growth of the chunk size. elapsed is the
// data time of the chunk (excluding connection setup). bytes <= 0 is ignored.
func (p *Profile) ChunkDone(bytes int64, elapsed time.Duration) {
	if bytes <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	p.observeLocked(bytes, elapsed)
	p.stalled = 0
	if p.mode != ModeChunked {
		return
	}
	p.okStreak++
	if p.okStreak >= GrowAfter {
		eff := p.effectiveLocked()
		p.chunk = growChunk(eff)
		p.okStreak = 0
	}
}

// ConnectionSetup reports the time one connection took to become usable.
// Non-positive values are ignored.
func (p *Profile) ConnectionSetup(d time.Duration) {
	if d <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := d.Seconds()
	if p.setup == 0 {
		p.setup = s
	} else {
		p.setup += ewmaAlpha * (s - p.setup)
	}
}

// Dropped reports the end of an attempt that did not complete. bytes is what
// the attempt put on the wire, life how long the connection lived (setup
// included). Only FailLink and FailSetup change the profile:
//
//   - FailLink records life in the survival window, remembers the speed at the
//     drop, halves the chunk size in chunked mode and breaks the success
//     streak.
//   - FailSetup only counts as an attempt without progress.
//
// An attempt counts as progress only if it advanced the transfer durably: in
// stream mode a drop with more bytes than any earlier dropped stream attempt;
// in chunked mode never (a cut-off chunk is lost; ChunkDone is the progress).
func (p *Profile) Dropped(bytes int64, life time.Duration, kind FailureKind) {
	if kind != FailLink && kind != FailSetup {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	if bytes < 0 {
		bytes = 0
	}
	progressed := false
	if kind == FailLink {
		if life < 0 {
			life = 0
		}
		if p.mode == ModeChunked {
			p.chunk = halveChunk(p.effectiveLocked())
		} else if bytes > p.bestStream {
			p.bestStream = bytes
			progressed = true
		}
		p.addDropLocked(life)
		switch {
		case p.speed > 0:
			p.dropSpeed = p.speed
		case life > 0 && bytes > 0:
			p.dropSpeed = float64(bytes) / life.Seconds()
		}
		p.okStreak = 0
	}
	if progressed {
		p.stalled = 0
	} else {
		p.stalled++
	}
}

// Succeeded reports that the transfer completed. It ends the transfer:
// per-transfer state resets and the next transfer starts in stream mode (rule
// 1 then decides immediately whether it must be chunked). Link knowledge
// (speed, drops, chunk size) is kept.
func (p *Profile) Succeeded() {
	p.BeginTransfer()
}

// BeginTransfer resets per-transfer state (mode, attempts without progress).
// Call it after a transfer that ended without Succeeded (failed or given up).
func (p *Profile) BeginTransfer() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stalled = 0
	p.bestStream = 0
	p.mode = ModeStream
}

// GiveUp reports that MaxNoProgress consecutive attempts made no progress.
// The caller then fails the job with error class link_unstable.
func (p *Profile) GiveUp() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stalled >= MaxNoProgress
}

// Mode returns the stored mode (updated by Decide).
func (p *Profile) Mode() Mode {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mode
}

// UseChunks is rule 1: true when a drop is known inside the window and the
// estimated time to stream size bytes (size/speed) exceeds the survival time.
// False when no drop is known, the speed is unknown or size <= 0.
func (p *Profile) UseChunks(size int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	return p.useChunksLocked(size)
}

// NextChunk is rule 2 and 3: the chunk size for the next attempt, never above
// remaining and never above MaxChunk. It is the smaller of the stored AIMD
// size and the survivability bound B*T_survive*0.5 (at least MinChunk),
// lifted by the setup-overhead floor B*20*t_setup unless that conflicts with
// survivability (then survivability wins). It returns 0 only for
// remaining <= 0.
func (p *Profile) NextChunk(remaining int64) int64 {
	if remaining <= 0 {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	s := p.effectiveLocked()
	if s > remaining {
		s = remaining
	}
	return s
}

// Decide chooses the mode and length of the next attempt for remaining
// missing bytes (the whole size at the start of a transfer).
//
// From stream mode it switches to chunked when UseChunks(remaining) holds and
// the chunk would be smaller than remaining. From chunked mode it returns to
// stream (rule 4) when the chunk size reaches remaining, or when no drop
// remains in the window and the speed is at least ImproveFactor times the
// speed at the last drop.
func (p *Profile) Decide(remaining int64) Step {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	if remaining <= 0 {
		return Step{Mode: p.mode}
	}
	if p.mode == ModeStream {
		if !p.useChunksLocked(remaining) {
			return Step{Mode: ModeStream, Len: remaining}
		}
		if p.chunk <= 0 {
			p.chunk = p.survivalBoundLocked()
		}
		if p.effectiveLocked() >= remaining {
			return Step{Mode: ModeStream, Len: remaining}
		}
		p.mode = ModeChunked
		p.okStreak = 0
	}
	s := p.effectiveLocked()
	if s >= remaining || p.improvedLocked() {
		p.mode = ModeStream
		return Step{Mode: ModeStream, Len: remaining}
	}
	return Step{Mode: ModeChunked, Len: s}
}

// Snapshot returns a copy of the current state.
func (p *Profile) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	t, known := p.surviveLocked()
	return Snapshot{
		Mode:         p.mode,
		Speed:        p.speed,
		Setup:        time.Duration(p.setup * float64(time.Second)),
		Survive:      t,
		SurviveKnown: known,
		Chunk:        p.effectiveLocked(),
		Stored:       p.chunk,
		OKStreak:     p.okStreak,
		Stalled:      p.stalled,
		Drops:        len(p.drops),
		DropSpeed:    p.dropSpeed,
	}
}

func (p *Profile) observeLocked(bytes int64, elapsed time.Duration) {
	if bytes <= 0 || elapsed <= 0 {
		return
	}
	s := float64(bytes) / elapsed.Seconds()
	if math.IsNaN(s) || s <= 0 {
		return
	}
	if s > maxSpeed {
		s = maxSpeed
	}
	if p.speed == 0 {
		p.speed = s
	} else {
		p.speed += ewmaAlpha * (s - p.speed)
	}
}

func (p *Profile) addDropLocked(life time.Duration) {
	p.drops = append(p.drops, drop{at: p.now(), life: life})
	if len(p.drops) > maxDrops {
		p.drops = append(p.drops[:0], p.drops[len(p.drops)-maxDrops:]...)
	}
}

// pruneLocked forgets drops older than the window.
func (p *Profile) pruneLocked() {
	if len(p.drops) == 0 {
		return
	}
	now := p.now()
	kept := p.drops[:0]
	for _, d := range p.drops {
		if now.Sub(d.at) <= p.window {
			kept = append(kept, d)
		}
	}
	p.drops = kept
}

func (p *Profile) surviveLocked() (time.Duration, bool) {
	if len(p.drops) == 0 {
		return 0, false
	}
	t := p.drops[0].life
	for _, d := range p.drops[1:] {
		if d.life < t {
			t = d.life
		}
	}
	return t, true
}

func (p *Profile) useChunksLocked(size int64) bool {
	if size <= 0 || len(p.drops) == 0 || p.speed <= 0 {
		return false
	}
	t, _ := p.surviveLocked()
	return float64(size)/p.speed > t.Seconds()
}

func (p *Profile) improvedLocked() bool {
	return len(p.drops) == 0 && p.dropSpeed > 0 && p.speed >= ImproveFactor*p.dropSpeed
}

// survivalBoundLocked is B*T_survive*SafetyFactor clamped to
// [MinChunk, MaxChunk]; MaxChunk when no drop is known, MinChunk when a drop
// is known but the speed is not.
func (p *Profile) survivalBoundLocked() int64 {
	t, known := p.surviveLocked()
	if !known {
		return MaxChunk
	}
	if p.speed <= 0 {
		return MinChunk
	}
	return clampChunk(p.speed * t.Seconds() * SafetyFactor)
}

// overheadFloorLocked is B*OverheadFactor*t_setup clamped to MaxChunk; 0 when
// the speed or the setup time is unknown.
func (p *Profile) overheadFloorLocked() int64 {
	if p.speed <= 0 || p.setup <= 0 {
		return 0
	}
	f := p.speed * OverheadFactor * p.setup
	if math.IsNaN(f) || f <= 0 {
		return 0
	}
	if f >= float64(MaxChunk) {
		return MaxChunk
	}
	return int64(f)
}

// effectiveLocked is min(survivability bound, max(stored, overhead floor)),
// always within [MinChunk, MaxChunk].
func (p *Profile) effectiveLocked() int64 {
	v := p.survivalBoundLocked()
	s := p.chunk
	if s <= 0 {
		s = v
	}
	if l := p.overheadFloorLocked(); l > s {
		s = l
	}
	if s > v {
		s = v
	}
	if s < MinChunk {
		s = MinChunk
	}
	if s > MaxChunk {
		s = MaxChunk
	}
	return s
}

func clampChunk(f float64) int64 {
	if math.IsNaN(f) || f < float64(MinChunk) {
		return MinChunk
	}
	if f >= float64(MaxChunk) {
		return MaxChunk
	}
	return int64(f)
}

func halveChunk(s int64) int64 {
	s /= 2
	if s < MinChunk {
		return MinChunk
	}
	return s
}

func growChunk(s int64) int64 {
	if s >= MaxChunk-s/2 {
		return MaxChunk
	}
	return s + s/2
}
