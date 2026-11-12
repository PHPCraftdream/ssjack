package vault

import (
	"bytes"
	"context"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

// LegacyOutputGuard captures authenticated version-1 credentials before Close.
// Version 2 requires the coordinator's confirmed linked-value admission instead.
func (v *Vault) LegacyOutputGuard(ctx context.Context, path string) (*outputguard.Snapshot, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || v.Version != 1 || verifyVaultCapture(ctx, path, v) != nil {
		return nil, outputguard.ErrGuard
	}
	snapshot, err := credentialGuard(v)
	if err != nil || ctx.Err() != nil {
		return nil, outputguard.ErrGuard
	}
	return snapshot, nil
}

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
	if journal := v.Rotation; journal != nil && journal.Phase != RotationCancelled && journal.Phase != RotationArchived {
		var seen [][]byte
		for _, target := range v.Targets {
			if len(target.PrivateKey) != 0 {
				seen = append(seen, target.PrivateKey)
			}
		}
		for _, secret := range [][]byte{journal.Original.PrivateKey, journal.NewPrivate} {
			if len(secret) == 0 {
				continue
			}
			duplicate := false
			for _, existing := range seen {
				if bytes.Equal(existing, secret) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			if !add(secret) {
				return nil, outputguard.ErrGuard
			}
			seen = append(seen, secret)
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
