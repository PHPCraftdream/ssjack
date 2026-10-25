package keyfile

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ktav-lang/golang/pure"
)

const (
	Magic        = "# ssjack encrypted key v1\n"
	MaxSize      = 256 * 1024
	MaxPlaintext = 64 * 1024
	Layers       = 1000
	MemoryKiB    = 1024 * 1024
	argonPasses  = 1
	argonThreads = 1
	saltSize     = 32
	nonceSize    = 12
	tagSize      = 16
)

type document struct {
	Version     int      `json:"version"`
	KDF         string   `json:"kdf"`
	MemoryKiB   int      `json:"memory_kib"`
	Passes      int      `json:"passes"`
	Parallelism int      `json:"parallelism"`
	Layers      int      `json:"layers"`
	Salts       []string `json:"salts"`
	Nonce       string   `json:"nonce"`
	Ciphertext  string   `json:"ciphertext"`
}

func IsContainer(data []byte) bool {
	return bytes.HasPrefix(data, []byte(Magic))
}

func newDocument() (document, error) {
	d := document{
		Version: 1, KDF: "argon2id-x4-hkdf-sha256", MemoryKiB: MemoryKiB,
		Passes: argonPasses, Parallelism: argonThreads, Layers: Layers,
	}
	for range 4 {
		salt := make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return document{}, err
		}
		d.Salts = append(d.Salts, base64.StdEncoding.EncodeToString(salt))
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return document{}, err
	}
	d.Nonce = base64.StdEncoding.EncodeToString(nonce)
	return d, nil
}

func (d document) header() ([]byte, [][]byte, []byte, error) {
	if d.Version != 1 || d.KDF != "argon2id-x4-hkdf-sha256" || d.MemoryKiB != MemoryKiB ||
		d.Passes != argonPasses || d.Parallelism != argonThreads || d.Layers != Layers || len(d.Salts) != 4 {
		return nil, nil, nil, errors.New("unsupported encrypted key parameters")
	}
	header := []byte("ssjack-key/v1\x00argon2id-x4-hkdf-sha256\x00")
	for _, value := range []int{d.Version, d.MemoryKiB, d.Passes, d.Parallelism, d.Layers} {
		header = binary.BigEndian.AppendUint32(header, uint32(value))
	}
	var salts [][]byte
	for _, encoded := range d.Salts {
		salt, err := decodeFixed(encoded, saltSize)
		if err != nil {
			return nil, nil, nil, errors.New("invalid encrypted key salt")
		}
		for _, previous := range salts {
			if bytes.Equal(previous, salt) {
				return nil, nil, nil, errors.New("encrypted key salts must be distinct")
			}
		}
		salts = append(salts, salt)
		header = append(header, salt...)
	}
	nonce, err := decodeFixed(d.Nonce, nonceSize)
	if err != nil {
		return nil, nil, nil, errors.New("invalid encrypted key nonce")
	}
	header = append(header, nonce...)
	return header, salts, nonce, nil
}

func decodeFixed(encoded string, size int) ([]byte, error) {
	if len(encoded) != base64.StdEncoding.EncodedLen(size) {
		return nil, errors.New("invalid encoded size")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) != size || base64.StdEncoding.EncodeToString(data) != encoded {
		return nil, errors.New("invalid base64 value")
	}
	return data, nil
}

func decode(data []byte) (document, []byte, error) {
	if len(data) > MaxSize || !IsContainer(data) {
		return document{}, nil, errors.New("invalid encrypted key document")
	}
	body := string(data[len(Magic):])
	value, err := pure.LoadsStrict(body)
	if err != nil {
		return document{}, nil, errors.New("invalid encrypted key Ktav")
	}
	root, ok := value.(map[string]any)
	if !ok || len(root) != 9 {
		return document{}, nil, errors.New("invalid encrypted key fields")
	}
	for _, field := range []string{"version", "kdf", "memory_kib", "passes", "parallelism", "layers", "salts", "nonce", "ciphertext"} {
		if _, ok := root[field]; !ok {
			return document{}, nil, fmt.Errorf("missing encrypted key field %q", field)
		}
	}
	var d document
	if err := pure.LoadsInto(body, &d); err != nil {
		return document{}, nil, errors.New("invalid encrypted key field types")
	}
	if _, _, _, err := d.header(); err != nil {
		return document{}, nil, err
	}
	if len(d.Ciphertext) > base64.StdEncoding.EncodedLen(MaxPlaintext+Layers*tagSize) {
		return document{}, nil, errors.New("encrypted key ciphertext is too large")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(d.Ciphertext)
	if err != nil || len(ciphertext) <= Layers*tagSize || len(ciphertext) > MaxPlaintext+Layers*tagSize ||
		base64.StdEncoding.EncodeToString(ciphertext) != d.Ciphertext {
		return document{}, nil, errors.New("invalid encrypted key ciphertext")
	}
	return d, ciphertext, nil
}

func encode(d document, ciphertext []byte) ([]byte, error) {
	d.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	body, err := pure.EmitCanonical(d)
	if err != nil {
		return nil, err
	}
	encoded := []byte(Magic + body)
	if len(encoded) > MaxSize {
		return nil, errors.New("encrypted key document is too large")
	}
	return encoded, nil
}
