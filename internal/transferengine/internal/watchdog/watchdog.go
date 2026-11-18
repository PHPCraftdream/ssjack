package watchdog

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/timer"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// DefaultStallLimit is how long a byte-moving session of a single-file upload
// or download (the whole stream or one part) may deliver no byte before the
// stall watchdog aborts it and counts it as a drop (docs/FILE-TRANSFER.md,
// "First attempt and measurements"). Options.StallLimit overrides it.
const DefaultStallLimit = 60 * time.Second

// StallTimer is the timer handle the watchdog drives; it is the timer package's
// Timer, aliased so existing users of this name keep working unchanged.
type StallTimer = timer.Timer

// StallClock creates the watchdog timers. Tests inject a virtual one so that no
// test waits on a real timer; the default is the wall clock.
type StallClock interface {
	// AfterFunc runs f once in its own goroutine after d, unless the returned
	// timer is stopped or re-armed first.
	AfterFunc(d time.Duration, f func()) StallTimer
}

// wallStallClock is the default StallClock.
type wallStallClock struct{}

func (wallStallClock) AfterFunc(d time.Duration, f func()) StallTimer { return time.AfterFunc(d, f) }

// Config is the engine's watchdog setting.
type Config struct {
	clock StallClock
	limit time.Duration
}

// NewConfig resolves the Options: nil clock is the wall clock, a zero limit is
// DefaultStallLimit. A negative limit is invalid.
func NewConfig(clock StallClock, limit time.Duration) (Config, error) {
	if limit < 0 {
		return Config{}, transfercore.Fail(transfercore.ClassInternal, "transfer stall limit is invalid")
	}
	if limit == 0 {
		limit = DefaultStallLimit
	}
	if clock == nil {
		clock = wallStallClock{}
	}
	return Config{clock: clock, limit: limit}, nil
}

// Session is the inactivity timer of one byte-moving session. It is armed when
// created and re-armed by every kick; when the limit passes without a kick it
// cancels the context it handed out and remembers that it did. Its goroutines
// are the timer's own: stop disarms the timer, so nothing outlives the session.
type Session struct {
	limit  time.Duration
	cancel context.CancelFunc

	mu      sync.Mutex
	timer   StallTimer
	fired   bool
	stopped bool
}

// Start derives the session context from parent and arms the timer.
// Cancelling parent cancels the session context as usual; the watchdog then
// never counts as having fired unless it fired first.
func (c Config) Start(parent context.Context) (*Session, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	s := &Session{limit: c.limit, cancel: cancel}
	s.mu.Lock()
	s.timer = c.clock.AfterFunc(c.limit, s.fire)
	s.mu.Unlock()
	return s, ctx
}

// fire is the timer callback: the session delivered no byte for the limit.
func (s *Session) fire() {
	s.mu.Lock()
	if s.stopped || s.fired {
		s.mu.Unlock()
		return
	}
	s.fired = true
	s.mu.Unlock()
	s.cancel()
}

// kick records activity: the session moved a byte, so the limit starts again.
func (s *Session) kick() {
	s.mu.Lock()
	if !s.stopped && !s.fired {
		s.timer.Reset(s.limit)
	}
	s.mu.Unlock()
}

// Stop disarms the watchdog and releases the session context. It reports
// whether the watchdog had fired before the stop, that is whether the session
// ended (or is ending) because of a stall. It is idempotent.
func (s *Session) Stop() (fired bool) {
	s.mu.Lock()
	s.stopped = true
	fired = s.fired
	s.timer.Stop()
	s.mu.Unlock()
	s.cancel()
	return fired
}

// Reader wraps the source of the session so its progress reaches the watchdog.
// The SSH stdin copy of a session reads the source, then writes what it read to
// the channel, then reads again, so the observation point is exact for both
// directions of trouble: a slow but moving link keeps asking for the next
// buffer and every call re-arms the timer, while a stuck write stops the calls
// and lets the limit run out. A read counts when it is asked for (the previous
// write was accepted) and when it returns bytes.
func (s *Session) Reader(r io.Reader) io.Reader { return &stallReader{r: r, s: s} }

// Writer wraps the sink of the session so its progress reaches the watchdog,
// the download counterpart of Reader. The remote output copy writes what the
// link delivered, then reads again, so a write that the sink accepted means the
// session moved a byte and re-arms the timer, while a link that delivers
// nothing stops the writes and lets the limit run out.
func (s *Session) Writer(w io.Writer) io.Writer { return &stallWriter{w: w, s: s} }

// stallReader reports the progress of the source to the watchdog.
type stallReader struct {
	r io.Reader
	s *Session
}

func (s *stallReader) Read(p []byte) (int, error) {
	s.s.kick()
	n, err := s.r.Read(p)
	if n > 0 {
		s.s.kick()
	}
	return n, err
}

// stallWriter reports the progress of the sink to the watchdog.
type stallWriter struct {
	w io.Writer
	s *Session
}

func (s *stallWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if n > 0 {
		s.s.kick()
	}
	return n, err
}

// Failure turns the cancellation caused by the watchdog into the link failure
// it stands for, so the planner sees a stall exactly like a drop. A cancel of
// the job's own context (jobCtx) keeps its class: the manager's cancel is a
// cancel even when the watchdog fired in the same instant. An error that is not
// a cancellation (the remote answered first) is left alone.
func Failure(jobCtx context.Context, err error, stalled bool) error {
	if err == nil || !stalled || jobCtx.Err() != nil {
		return err
	}
	if transfercore.ClassOf(err) != transfercore.ClassCancelled {
		return err
	}
	return transferremote.LinkFailure()
}
