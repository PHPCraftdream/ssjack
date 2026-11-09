package vault

import "errors"

// AdmitAt checks and publishes owner queue state under the revision lock.
// The callback must not call Session methods or retain database buffers.
func (s *Session) AdmitAt(expected uint64, admit func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || admit == nil {
		return errors.New("database session does not accept owner admission")
	}
	if expected != s.revision {
		return ErrOwnerRevision
	}
	return admit()
}
