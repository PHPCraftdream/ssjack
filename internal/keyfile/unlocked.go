package keyfile

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
)

// Unlocked owns a memory-only master; Close must end its lifetime.
type Unlocked struct {
	mu     sync.Mutex
	master []byte
	d      document
}

func NewUnlocked(password []byte, version int) (*Unlocked, error) {
	return newUnlocked(password, version, argonDerive)
}

func newUnlocked(password []byte, version int, derive deriveFunc) (*Unlocked, error) {
	d, err := newDocument()
	if err != nil {
		return nil, err
	}
	d.Version = version
	_, salts, _, err := d.header()
	if err != nil {
		return nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, err
	}
	return &Unlocked{master: master, d: d}, nil
}

func Unlock(encoded, password []byte) ([]byte, *Unlocked, error) {
	return unlock(encoded, password, argonDerive)
}

func unlock(encoded, password []byte, derive deriveFunc) ([]byte, *Unlocked, error) {
	d, ciphertext, err := decode(encoded)
	if err != nil {
		return nil, nil, err
	}
	header, salts, nonce, err := d.header()
	if err != nil {
		return nil, nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := decryptLayers(ciphertext, master, nonce, header)
	if err != nil {
		clear(master)
		return nil, nil, err
	}
	payload, err := unwrapPayload(d, plaintext)
	if err != nil {
		clear(master)
		return nil, nil, err
	}
	d.Ciphertext = ""
	return payload, &Unlocked{master: master, d: d}, nil
}

func (u *Unlocked) Close() {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	clear(u.master)
	u.master = nil
}

// Seal reuses the authenticated salts/master but always generates a fresh nonce.
func (u *Unlocked) Seal(plaintext []byte) ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.master) != 32 {
		return nil, errors.New("encrypted storage context is closed")
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, errors.New("invalid encrypted payload size")
	}
	d := u.d
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	d.Nonce = base64.StdEncoding.EncodeToString(nonce)
	header, _, _, err := d.header()
	if err != nil {
		return nil, err
	}
	envelope, err := wrapPayload(d, plaintext)
	if err != nil {
		return nil, err
	}
	defer clear(envelope)
	ciphertext, err := encryptLayers(envelope, u.master, nonce, header, "storage")
	if err != nil {
		return nil, err
	}
	defer clear(ciphertext)
	return encode(d, ciphertext)
}

// GenerateIdentity returns owned public/private payloads, never files.
func (u *Unlocked) GenerateIdentity() ([]byte, []byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.master) != 32 {
		return nil, nil, errors.New("encrypted storage context is closed")
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	d := u.d
	d.Nonce = base64.StdEncoding.EncodeToString(nonce)
	header, _, _, err := d.header()
	if err != nil {
		return nil, nil, err
	}
	return generateIdentity(u.master, nonce, header)
}
