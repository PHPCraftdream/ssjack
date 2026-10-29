package keyfile

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"runtime"

	"github.com/PHPCraftdream/ssjack/internal/kdfgate"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

type deriveFunc func(password, salt []byte) []byte

func argonDerive(password, salt []byte) []byte {
	key := argon2.IDKey(password, salt, argonPasses, MemoryKiB, argonThreads, 32)
	// Reclaim the previous workspace before the next 1 GiB invocation.
	runtime.GC()
	return key
}

func masterKey(password []byte, salts [][]byte, derive deriveFunc) ([]byte, error) {
	if len(password) == 0 || len(password) > 16*1024 {
		return nil, errors.New("passphrase must contain 1 to 16384 bytes")
	}
	release, err := kdfgate.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer release()
	combined := make([]byte, 0, 4*32)
	defer func() { clear(combined) }()
	for _, salt := range salts {
		part := derive(password, salt)
		if len(part) != 32 {
			clear(part)
			return nil, errors.New("invalid Argon2id output")
		}
		combined = append(combined, part...)
		clear(part)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, combined, nil, []byte("ssjack-key/v1/master")), key); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

func layer(master, baseNonce, header []byte, purpose string, index int) (cipher.AEAD, []byte, []byte, error) {
	domain := "ssjack-key/v1/"
	if bytes.HasPrefix(header, []byte("ssjack-key/v2\x00")) {
		domain = "ssjack-key/v2/"
	}
	context := binary.BigEndian.AppendUint32([]byte(domain+purpose+"/layer/"), uint32(index))
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, context), key); err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce := append([]byte(nil), baseNonce...)
	counter := binary.BigEndian.Uint32(nonce[len(nonce)-4:]) ^ uint32(index)
	binary.BigEndian.PutUint32(nonce[len(nonce)-4:], counter)
	aad := append(append([]byte(nil), header...), context...)
	return aead, nonce, aad, nil
}

func encryptLayers(plaintext, master, nonce, header []byte, purpose string) ([]byte, error) {
	data := make([]byte, len(plaintext), len(plaintext)+Layers*tagSize)
	copy(data, plaintext)
	for index := range Layers {
		aead, layerNonce, aad, err := layer(master, nonce, header, purpose, index)
		if err != nil {
			clear(data)
			return nil, err
		}
		data = aead.Seal(data[:0], layerNonce, data, aad)
	}
	return data, nil
}

func decryptLayers(ciphertext, master, nonce, header []byte) ([]byte, error) {
	data := append([]byte(nil), ciphertext...)
	for index := Layers - 1; index >= 0; index-- {
		aead, layerNonce, aad, err := layer(master, nonce, header, "storage", index)
		if err != nil {
			clear(data)
			return nil, err
		}
		opened, err := aead.Open(data[:0], layerNonce, data, aad)
		if err != nil {
			clear(data)
			return nil, errors.New("failed to unlock encrypted key")
		}
		data = opened
	}
	return data, nil
}

// Seal encrypts the entire previous ciphertext on each of 1000 layers.
func Seal(plaintext, password []byte) ([]byte, error) {
	return seal(plaintext, password, argonDerive)
}

// SealVersion preserves an existing format; new containers use Seal.
func SealVersion(plaintext, password []byte, version int) ([]byte, error) {
	return sealVersion(plaintext, password, version, argonDerive)
}

func seal(plaintext, password []byte, derive deriveFunc) ([]byte, error) {
	return sealVersion(plaintext, password, 2, derive)
}

func sealVersion(plaintext, password []byte, version int, derive deriveFunc) ([]byte, error) {
	if version != 1 && version != 2 {
		return nil, errors.New("unsupported encrypted container version")
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, errors.New("private key payload must contain 1 to 65536 bytes")
	}
	d, err := newDocument()
	d.Version = version
	if err != nil {
		return nil, err
	}
	return sealDocument(d, plaintext, password, derive)
}

func sealDocument(d document, plaintext, password []byte, derive deriveFunc) ([]byte, error) {
	header, salts, nonce, err := d.header()
	if err != nil {
		return nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	envelope, err := wrapPayload(d, plaintext)
	if err != nil {
		return nil, err
	}
	defer clear(envelope)
	ciphertext, err := encryptLayers(envelope, master, nonce, header, "storage")
	if err != nil {
		return nil, err
	}
	defer clear(ciphertext)
	return encode(d, ciphertext)
}

func Open(encoded, password []byte) ([]byte, error) {
	return open(encoded, password, argonDerive)
}

func open(encoded, password []byte, derive deriveFunc) ([]byte, error) {
	d, ciphertext, err := decode(encoded)
	if err != nil {
		return nil, err
	}
	header, salts, nonce, err := d.header()
	if err != nil {
		return nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	plaintext, err := decryptLayers(ciphertext, master, nonce, header)
	if err != nil {
		return nil, err
	}
	return unwrapPayload(d, plaintext)
}
