package vault

import (
	"errors"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

func (t Target) validateAuthentication() error {
	if len(t.Password) != 0 {
		if len(t.PrivateKey) != 0 || len(t.Password) > 4096 {
			return errors.New("select exactly one bounded SSH password or private key")
		}
		return nil
	}
	if len(t.PrivateKey) == 0 || len(t.PrivateKey) > keyfile.MaxPlaintext {
		return errors.New("invalid private key size")
	}
	if _, err := ssh.ParsePrivateKey(t.PrivateKey); err != nil {
		return errors.New("vault private key must be an unencrypted in-memory SSH key")
	}
	return nil
}
