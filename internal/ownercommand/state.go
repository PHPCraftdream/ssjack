package ownercommand

import "errors"

var (
	ErrCancelled = errors.New("owner command cancelled; no automatic retry")
	ErrOperation = errors.New("owner command failed or remains incomplete; inspect persistence and pending recovery before retrying")
)

// State belongs to one terminal model, not to a background worker.
type State struct {
	Request  Request
	Finished bool
	Err      error
}

func (s *State) Result() error {
	if !s.Finished && s.Err == nil {
		return ErrCancelled
	}
	return s.Err
}
