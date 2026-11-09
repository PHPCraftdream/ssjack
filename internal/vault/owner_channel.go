package vault

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
)

// OwnerPeer borrows only the closed owner protocol capability, never its master.
func (s *Session) OwnerPeer(path string, binding [32]byte) (*ownerpacket.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.exportKey == nil || s.state == nil || s.state.Version != 2 || s.savedCipher == ([32]byte{}) {
		return nil, errors.New("owner channel requires an authenticated saved ciphertext origin")
	}
	encoded, err := readEncoded(path)
	if err != nil || sha256.Sum256(encoded) != s.savedCipher {
		return nil, ErrOwnerRevision
	}
	return ownerpacket.NewServer(s.exportKey, binding, s.savedCipher)
}

// LocalOwnerPeer shares the current invocation's unlock, not an application grant.
func (s *Session) LocalOwnerPeer(binding [32]byte) (*ownerpacket.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.exportKey == nil {
		return nil, errors.New("owner channel context is unavailable")
	}
	return ownerpacket.NewClient(s.exportKey, binding)
}

// OwnerUnlock owns one helper unlock and can rotate only its protocol peers.
// It has no plaintext, stored-secret, password, or master getter.
type OwnerUnlock struct {
	mu      sync.Mutex
	key     *keyfile.Unlocked
	binding [32]byte
}

func OpenOwnerUnlock(path string, password []byte, binding [32]byte) (*OwnerUnlock, error) {
	loaded, err := Load(path, password)
	if err != nil {
		return nil, errors.New("cannot authenticate owner database")
	}
	return AdoptOwnerUnlock(loaded, binding)
}

// AdoptOwnerUnlock consumes a read-only authenticated vault without another KDF.
func AdoptOwnerUnlock(loaded *Vault, binding [32]byte) (*OwnerUnlock, error) {
	if loaded == nil {
		return nil, errors.New("owner channel requires an authenticated vault")
	}
	if loaded.Version != 2 || loaded.unlocked == nil || loaded.writer != nil || binding == ([32]byte{}) {
		loaded.Close()
		return nil, errors.New("owner channel requires a read-only directory unlock")
	}
	key := loaded.unlocked
	loaded.unlocked = nil
	loaded.Close()
	return &OwnerUnlock{key: key, binding: binding}, nil
}
func (u *OwnerUnlock) Peer() (*ownerpacket.Client, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.key == nil {
		return nil, errors.New("owner helper context is closed")
	}
	return ownerpacket.NewClient(u.key, u.binding)
}
func (u *OwnerUnlock) Close() {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.key != nil {
		u.key.Close()
		u.key = nil
	}
}
