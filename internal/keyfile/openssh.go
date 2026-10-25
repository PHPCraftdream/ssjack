package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/ssh"
)

func wipeSSHPrivate(private any) {
	switch key := private.(type) {
	case *ed25519.PrivateKey:
		clear(*key)
	case ed25519.PrivateKey:
		clear(key)
	}
}

func marshalableSSHPrivate(private any) any {
	if key, ok := private.(*ed25519.PrivateKey); ok {
		return *key
	}
	return private
}

func RequiresPassphrase(data []byte) (bool, error) {
	if len(data) == 0 || len(data) > 1024*1024 {
		return false, errors.New("invalid SSH key input size")
	}
	if IsContainer(data) {
		return true, nil
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return false, errors.New("expected exactly one PEM or OpenSSH private key")
	}
	clear(block.Bytes)
	private, err := ssh.ParseRawPrivateKey(data)
	if err == nil {
		wipeSSHPrivate(private)
		return false, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return true, nil
	}
	return false, errors.New("unsupported or invalid SSH private key")
}

// ImportSSH returns a canonical plaintext payload for encrypted in-memory storage.
func ImportSSH(data, password []byte) ([]byte, error) {
	var private any
	var err error
	if IsContainer(data) {
		plaintext, openErr := Open(data, password)
		if openErr != nil {
			return nil, openErr
		}
		defer clear(plaintext)
		private, err = ssh.ParseRawPrivateKey(plaintext)
	} else {
		encrypted, parseErr := RequiresPassphrase(data)
		if parseErr != nil {
			return nil, parseErr
		}
		if encrypted {
			private, err = ssh.ParseRawPrivateKeyWithPassphrase(data, password)
		} else {
			private, err = ssh.ParseRawPrivateKey(data)
		}
	}
	if err != nil {
		return nil, errors.New("failed to import SSH private key")
	}
	defer wipeSSHPrivate(private)
	block, err := ssh.MarshalPrivateKey(marshalableSSHPrivate(private), "ssjack imported key")
	if err != nil {
		return nil, err
	}
	defer clear(block.Bytes)
	plaintext := pem.EncodeToMemory(block)
	if len(plaintext) > MaxPlaintext {
		clear(plaintext)
		return nil, errors.New("imported SSH key exceeds the container payload limit")
	}
	return plaintext, nil
}

func ExportSSH(plaintext, password []byte) ([]byte, error) {
	if len(password) == 0 || len(password) > 16*1024 {
		return nil, errors.New("OpenSSH export requires a nonempty passphrase of at most 16384 bytes")
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, errors.New("invalid private key payload size")
	}
	private, err := ssh.ParseRawPrivateKey(plaintext)
	if err != nil {
		return nil, errors.New("invalid in-memory SSH private key")
	}
	defer wipeSSHPrivate(private)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(marshalableSSHPrivate(private), "ssjack exported key", password)
	if err != nil {
		return nil, err
	}
	defer clear(block.Bytes)
	return pem.EncodeToMemory(block), nil
}

func PublicSSH(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, errors.New("invalid private key payload size")
	}
	signer, err := ssh.ParsePrivateKey(plaintext)
	if err != nil {
		return nil, errors.New("invalid in-memory SSH private key")
	}
	return ssh.MarshalAuthorizedKey(signer.PublicKey()), nil
}
