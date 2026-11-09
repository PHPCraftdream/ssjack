package vault

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

// RememberRemoteMCPAt records a private preference, never a launch grant.
// Success queues encrypted persistence; the caller must inspect its save receipt.
func (s *Session) RememberRemoteMCPAt(ctx context.Context, expected uint64, digest [32]byte, profile string, selected []mcpdirectory.Binding) error {
	if s == nil || ctx == nil || ctx.Err() != nil || digest == ([32]byte{}) || len(selected) > mcpdirectory.MaxSelections {
		return mcpdirectory.ErrChanged
	}
	owned := append([]mcpdirectory.Binding{}, selected...)
	return s.ApplyAt(expected, func(candidate *Vault) error {
		// Apply holds s.mu; do not call another Session method here.
		if ctx.Err() != nil || s.saved != expected || s.saveErr != nil || s.savedCipher != digest || (candidate.OwnerStore != nil && candidate.OwnerStore.Pending != nil) {
			return mcpdirectory.ErrChanged
		}
		if _, exists := candidate.Targets[profile]; !exists {
			return mcpdirectory.ErrChanged
		}
		if candidate.RemoteMCP == nil {
			if len(owned) != 0 {
				return mcpdirectory.ErrChanged
			}
			return nil
		}
		if err := candidate.RemoteMCP.Remember(profile, owned); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return mcpdirectory.ErrChanged
		}
		return nil
	})
}
