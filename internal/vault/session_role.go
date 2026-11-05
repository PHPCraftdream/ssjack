package vault

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
)

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
