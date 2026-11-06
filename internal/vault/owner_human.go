package vault

import (
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/ssh"
)

// HumanSSH privately captures one human-permitted login from an exact saved file.
// It never returns stored credential bytes or adopts a different ciphertext.
func (u *OwnerUnlock) HumanSSH(path string, expected [32]byte, server, account string) (*ssh.ClientConfig, string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.key == nil || expected == ([32]byte{}) {
		return nil, "", errors.New("owner human SSH context is unavailable")
	}
	encoded, err := readEncoded(path)
	if err != nil || sha256.Sum256(encoded) != expected {
		return nil, "", ErrOwnerRevision
	}
	plaintext, err := u.key.Open(encoded)
	if err != nil {
		return nil, "", errors.New("owner human SSH snapshot did not authenticate")
	}
	defer clear(plaintext)
	loaded, err := unmarshal(plaintext)
	if err != nil {
		return nil, "", errors.New("owner human SSH snapshot is invalid")
	}
	defer loaded.Close()
	profile, err := loaded.AccountProfile(server, account)
	if err != nil {
		return nil, "", err
	}
	target := loaded.Targets[profile]
	if err := target.RequireUsage("human"); err != nil {
		return nil, "", err
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, "", err
	}
	return config, target.Address, nil
}
