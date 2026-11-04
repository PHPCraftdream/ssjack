package keyfile

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// SSHProxyBinding privately binds route and selected credentials under a distinct domain.
func (u *Unlocked) SSHProxyBinding(identity, credentials []byte) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if u == nil || len(identity) == 0 || len(identity) > MaxPlaintext || len(credentials) == 0 || len(credentials) > 8192 {
		return result, errors.New("invalid SSH proxy binding input")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.master) != 32 {
		return result, errors.New("encrypted storage context is closed")
	}
	derive := hmac.New(sha256.New, u.master)
	derive.Write([]byte("ssjack/ssh-proxy-binding/key/v1\x00"))
	key := derive.Sum(nil)
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("ssjack/ssh-proxy-binding/value/v1\x00"))
	var size [8]byte
	for _, value := range [][]byte{identity, credentials} {
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		mac.Write(size[:])
		mac.Write(value)
	}
	copy(result[:], mac.Sum(nil))
	return result, nil
}

// SSHPasswordBinding returns an opaque grant binding, not an unkeyed verifier.
// Only the unlocked owner can recompute it; changing the vault master revokes it.
func (u *Unlocked) SSHPasswordBinding(identity, password []byte) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if u == nil || len(identity) == 0 || len(identity) > MaxPlaintext || len(password) == 0 || len(password) > 4096 {
		return result, errors.New("invalid SSH password binding input")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.master) != 32 {
		return result, errors.New("encrypted storage context is closed")
	}
	derive := hmac.New(sha256.New, u.master)
	derive.Write([]byte("ssjack/ssh-password-binding/key/v1\x00"))
	key := derive.Sum(nil)
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("ssjack/ssh-password-binding/value/v1\x00"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(identity)))
	mac.Write(size[:])
	mac.Write(identity)
	binary.BigEndian.PutUint64(size[:], uint64(len(password)))
	mac.Write(size[:])
	mac.Write(password)
	copy(result[:], mac.Sum(nil))
	return result, nil
}
