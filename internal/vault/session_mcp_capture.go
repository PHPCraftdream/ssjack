package vault

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
)

// RemoteMCPCapture privately captures enabled owner-confirmed MCP records from
// one authenticated unchanged vault before ownership adoption. The retained
// authentication must match the canonical payload and the current on-disk
// ciphertext both before the capture is assembled and again at its return
// boundary; a replaced or edited database revokes the newly owned copies and
// returns only the fixed refusal. The returned capture survives later Vault
// edits, adoption and close and performs no network effect, second unlock or
// per-operation KDF.
func (v *Vault) RemoteMCPCapture(ctx context.Context, path string, digest [32]byte, profile string, bindings []mcpdirectory.Binding) (*mcpgrant.Capture, error) {
	return v.remoteMCPCapture(ctx, path, digest, profile, bindings, nil)
}

// remoteMCPCapture is the admission core. The mutate seam exists only for
// deterministic tests of the across-construction window; production callers
// pass nil. It must never mutate the vault's memory state, which would break
// the authenticated canonical-payload comparison.
func (v *Vault) remoteMCPCapture(ctx context.Context, path string, digest [32]byte, profile string, bindings []mcpdirectory.Binding, mutate func()) (*mcpgrant.Capture, error) {
	if v == nil || ctx == nil || ctx.Err() != nil {
		return nil, mcpgrant.ErrGrant
	}
	if verifyVaultCapture(ctx, path, v) != nil {
		return nil, mcpgrant.ErrGrant
	}
	if digest == ([32]byte{}) || digest != v.revision {
		return nil, mcpgrant.ErrGrant
	}
	if v.OwnerStore != nil && v.OwnerStore.Pending != nil {
		return nil, mcpgrant.ErrGrant
	}
	if _, exists := v.Targets[profile]; !exists {
		return nil, mcpgrant.ErrGrant
	}
	if v.RemoteMCP == nil {
		return nil, mcpgrant.ErrGrant
	}
	records, err := confirmedMCPRecords(v.RemoteMCP, bindings)
	if err != nil {
		return nil, err
	}
	capture, err := mcpgrant.NewCapture(ctx, profile, 0, digest, records)
	if err != nil {
		return nil, err
	}
	// A fresh adoption session starts at revision zero; binding that revision
	// makes later database edits invalidate the choice instead of silently
	// adopting changed endpoints or credentials. The origin must still be the
	// authenticated current ciphertext once the owned copies exist.
	if mutate != nil {
		mutate()
	}
	if verifyVaultCapture(ctx, path, v) != nil {
		capture.Close(ctx)
		return nil, mcpgrant.ErrGrant
	}
	return capture, nil
}

// RemoteMCPCaptureAt revalidates one exact saved session state under the
// session-managed revision and saved-cipher gates and privately captures the
// enabled confirmed records. It returns capability material only: credential
// values never leave the session, and no network effect, second unlock or
// per-operation KDF occurs.
func (s *Session) RemoteMCPCaptureAt(ctx context.Context, expected uint64, digest [32]byte, profile string, bindings []mcpdirectory.Binding) (*mcpgrant.Capture, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, mcpgrant.ErrGrant
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Same fixed-state gate as OutputGuardAt: the capture is only valid for the
	// exact saved revision whose digest the caller already proved.
	if s.closed || s.closing || s.state == nil || s.revision != expected || s.saved != expected || s.saveErr != nil || digest == ([32]byte{}) || digest != s.savedCipher {
		return nil, mcpgrant.ErrGrant
	}
	if s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil {
		return nil, mcpgrant.ErrGrant
	}
	if _, exists := s.state.Targets[profile]; !exists {
		return nil, mcpgrant.ErrGrant
	}
	if s.state.RemoteMCP == nil {
		return nil, mcpgrant.ErrGrant
	}
	records, err := confirmedMCPRecords(s.state.RemoteMCP, bindings)
	if err != nil {
		return nil, err
	}
	return mcpgrant.NewCapture(ctx, profile, expected, digest, records)
}

// confirmedMCPRecords admits a concrete non-empty confirmed choice against the
// live directory: no duplicate accounts and every binding must still match the
// live enabled binding exactly.
func confirmedMCPRecords(directory *mcpdirectory.Directory, bindings []mcpdirectory.Binding) ([]mcpgrant.Record, error) {
	if directory == nil || len(bindings) == 0 || len(bindings) > mcpdirectory.MaxSelections {
		return nil, mcpgrant.ErrGrant
	}
	records := make([]mcpgrant.Record, 0, len(bindings))
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if _, dup := seen[binding.AccountID]; dup {
			return nil, mcpgrant.ErrGrant
		}
		seen[binding.AccountID] = struct{}{}
		live, err := directory.CurrentBinding(binding.AccountID)
		if err != nil || live != binding {
			return nil, mcpgrant.ErrGrant
		}
		records = append(records, mcpgrant.Record{
			ServerID:  binding.ServerID,
			AccountID: binding.AccountID,
			Server:    directory.Servers[binding.ServerID],
			Account:   directory.Accounts[binding.AccountID],
		})
	}
	return records, nil
}
