package ownercommand

import "errors"

var (
	ErrCancelled  = errors.New("owner command cancelled; no automatic retry")
	ErrOperation  = errors.New("owner command failed or remains incomplete; inspect persistence and pending recovery before retrying")
	ErrIncomplete = errors.New("owner command ended without completing or being cancelled; inspect the terminal transcript")
)

// CancelError is ErrCancelled plus the fixed trigger that ended the command and
// the number of focus moves before it, so a failure report can tell a
// deliberate key from a terminal artefact. It never carries input.
type CancelError struct {
	Cause string
	Moves int
}

func (e CancelError) Error() string        { return ErrCancelled.Error() }
func (e CancelError) Is(target error) bool { return target == ErrCancelled }

// State belongs to one terminal model, not to a background worker.
type State struct {
	Request  Request
	Finished bool
	Err      error
	Moves    int // Form focus moves handled so far.
}

// Cancel ends the command as a deliberate cancellation caused by trigger.
func (s *State) Cancel(trigger string) { s.Err = CancelError{Cause: trigger, Moves: s.Moves} }

func (s *State) Result() error {
	if !s.Finished && s.Err == nil {
		return ErrIncomplete
	}
	return s.Err
}
