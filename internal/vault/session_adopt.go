package vault

import (
	"context"
	"crypto/sha256"
	"errors"
)

func verifySessionAdoption(ctx context.Context, path string, v *Vault) error {
	if ctx == nil {
		return errors.New("database session requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.Version != 2 {
		return errors.New("migrate the database before opening the directory editor")
	}
	return verifyVaultCapture(ctx, path, v)
}

func verifyVaultCapture(ctx context.Context, path string, v *Vault) error {
	if v.unlocked == nil || v.payloadHash == ([sha256.Size]byte{}) {
		return errors.New("database session requires an authenticated unchanged vault")
	}
	payload, err := marshal(v)
	if err != nil {
		return err
	}
	matches := sha256.Sum256(payload) == v.payloadHash
	clear(payload)
	if !matches {
		return errors.New("vault was edited before session adoption")
	}
	encoded, err := readEncoded(path)
	if err != nil {
		return err
	}
	if sha256.Sum256(encoded) != v.revision {
		return errors.New("vault changed before session adoption")
	}
	return ctx.Err()
}

// SavedCipherDigest identifies a completed encrypted snapshot, not authority.
// It never returns a plaintext digest, credential, passphrase or master key.
func (s *Session) SavedCipherDigest() ([sha256.Size]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.saveErr != nil || s.saved != s.revision || s.savedCipher == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, errors.New("database snapshot is not fully saved")
	}
	return s.savedCipher, nil
}
