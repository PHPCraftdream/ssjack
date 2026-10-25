package keyfile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

// Generate derives Ed25519 bytes from the secret and fresh public parameters.
func Generate(password []byte) ([]byte, []byte, error) {
	return generate(password, argonDerive)
}

func generate(password []byte, derive deriveFunc) ([]byte, []byte, error) {
	d, err := newDocument()
	if err != nil {
		return nil, nil, err
	}
	return generateDocument(d, password, derive)
}

// GenerateRecovery also returns an owned plaintext payload for in-memory rotation.
func GenerateRecovery(password []byte) ([]byte, []byte, []byte, error) {
	d, err := newDocument()
	if err != nil {
		return nil, nil, nil, err
	}
	return generateMaterial(d, password, argonDerive)
}

func generateDocument(d document, password []byte, derive deriveFunc) ([]byte, []byte, error) {
	encoded, public, plaintext, err := generateMaterial(d, password, derive)
	clear(plaintext)
	return encoded, public, err
}

func generateMaterial(d document, password []byte, derive deriveFunc) ([]byte, []byte, []byte, error) {
	header, salts, nonce, err := d.header()
	if err != nil {
		return nil, nil, nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(master)
	seed, err := deriveSeed(master, nonce, header)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "ssjack derived Ed25519 key")
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(block.Bytes)
	plaintext := pem.EncodeToMemory(block)
	succeeded := false
	defer func() {
		if !succeeded {
			clear(plaintext)
		}
	}()
	ciphertext, err := encryptLayers(plaintext, master, nonce, header, "storage")
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(ciphertext)
	encoded, err := encode(d, ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return nil, nil, nil, err
	}
	succeeded = true
	return encoded, ssh.MarshalAuthorizedKey(public), plaintext, nil
}

func deriveSeed(master, nonce, header []byte) ([]byte, error) {
	ciphertext, err := encryptLayers([]byte("ssjack derived Ed25519 seed v1"), master, nonce, header, "keygen")
	if err != nil {
		return nil, err
	}
	defer clear(ciphertext)
	seed := sha256.Sum256(ciphertext)
	return seed[:], nil
}
