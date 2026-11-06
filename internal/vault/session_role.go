package vault

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
)

// OwnerBinding identifies the held endpoint, never an authorization grant.
func (s *Session) OwnerBinding() ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer == nil || s.closed || s.closing {
		return [32]byte{}, ErrWriterRole
	}
	return s.writer.binding, nil
}

// AcceptOwner borrows admission, not listener-close or database-key authority.
// The service must join its peers before closing this session.
func (s *Session) AcceptOwner(ctx context.Context) (ownerlocal.Connection, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrWriterRole
	}
	s.mu.Lock()
	role, unavailable := s.writer, s.closed || s.closing
	s.mu.Unlock()
	if role == nil || unavailable {
		return nil, ErrWriterRole
	}
	return role.accept(ctx)
}
