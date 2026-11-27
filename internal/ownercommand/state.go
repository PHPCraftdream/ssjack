package ownercommand

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	ErrCancelled  = errors.New("owner command cancelled; no automatic retry")
	ErrOperation  = errors.New("owner command failed or remains incomplete; inspect persistence and pending recovery before retrying")
	ErrIncomplete = errors.New("owner command ended without completing or being cancelled; inspect the terminal transcript")
)

// traceLimit bounds the event trace so a failure line stays short enough to
// survive terminal wrapping.
const traceLimit = 16

// CancelError is ErrCancelled plus the fixed trigger that ended the command,
// the number of focus moves before it and the recent event trace, so a failure
// report can tell a deliberate key from a terminal artefact. It never carries input.
type CancelError struct {
	Cause string
	Moves int
	Trace string
}

func (e CancelError) Error() string        { return ErrCancelled.Error() }
func (e CancelError) Is(target error) bool { return target == ErrCancelled }

// IncompleteError is ErrIncomplete plus the recent event trace.
type IncompleteError struct{ Trace string }

func (e IncompleteError) Error() string        { return ErrIncomplete.Error() }
func (e IncompleteError) Is(target error) bool { return target == ErrIncomplete }

// State belongs to one terminal model, not to a background worker.
type State struct {
	Request  Request
	Finished bool
	Err      error
	Moves    int // Form focus moves handled so far.

	started time.Time
	trace   []string
}

// Note records one event of a fixed vocabulary (key names, secret read start
// and result) with the milliseconds since the first event. It keeps the last
// traceLimit events and never receives input text.
func (s *State) Note(event string) {
	now := time.Now()
	if s.started.IsZero() {
		s.started = now
	}
	if len(s.trace) == traceLimit {
		copy(s.trace, s.trace[1:])
		s.trace = s.trace[:traceLimit-1]
	}
	s.trace = append(s.trace, event+"@"+strconv.FormatInt(now.Sub(s.started).Milliseconds(), 10))
}

func (s *State) events() string { return strings.Join(s.trace, ",") }

// Cancel ends the command as a deliberate cancellation caused by trigger.
func (s *State) Cancel(trigger string) {
	s.Err = CancelError{Cause: trigger, Moves: s.Moves, Trace: s.events()}
}

func (s *State) Result() error {
	if !s.Finished && s.Err == nil {
		return IncompleteError{Trace: s.events()}
	}
	return s.Err
}
