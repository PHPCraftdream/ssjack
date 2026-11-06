package vault

import "github.com/PHPCraftdream/ssjack/internal/outputguard"

// OutputGuardAt returns a private capability for one confirmed database state.
// Linked application values must be added separately before model admission.
func (s *Session) OutputGuardAt(expected uint64, digest [32]byte) (*outputguard.Snapshot, error) {
	if s == nil {
		return nil, outputguard.ErrGuard
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.state == nil || s.revision != expected || s.saved != expected || s.saveErr != nil || digest == ([32]byte{}) || digest != s.savedCipher {
		return nil, outputguard.ErrGuard
	}
	if s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil {
		return nil, outputguard.ErrGuard
	}
	return credentialGuard(s.state)
}

func credentialGuard(v *Vault) (*outputguard.Snapshot, error) {
	patterns := make([][]byte, 0)
	total := 0
	add := func(value []byte) bool {
		if len(value) == 0 {
			return true
		}
		if len(patterns) == outputguard.MaxPatterns || len(value) > outputguard.MaxPatternSize || len(value) > outputguard.MaxPatternBytes-total {
			return false
		}
		patterns = append(patterns, value)
		total += len(value)
		return true
	}
	for _, target := range v.Targets {
		if !add(target.Password) || !add(target.PrivateKey) || (target.Proxy != nil && !add(target.Proxy.Password)) {
			return nil, outputguard.ErrGuard
		}
	}
	if v.OwnerStore != nil && !add(v.OwnerStore.Master) {
		return nil, outputguard.ErrGuard
	}
	if v.RemoteMCP != nil {
		for _, account := range v.RemoteMCP.Accounts {
			if !add(account.Auth.Secret) {
				return nil, outputguard.ErrGuard
			}
			for _, header := range account.Headers {
				if !add(header.Value) {
					return nil, outputguard.ErrGuard
				}
			}
		}
	}
	return outputguard.New(patterns)
}
