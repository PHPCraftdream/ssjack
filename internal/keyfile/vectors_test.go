package keyfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/ktav-lang/golang/pure"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// This reference builds headers, envelopes, and layers without production helpers.
func TestIndependentFixedParameterVectors(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			password, payload := []byte("vector secret"), []byte("vector payload")
			d := document{Version: version, KDF: "argon2id-x4-hkdf-sha256", MemoryKiB: 1048576, Passes: 1, Parallelism: 1, Layers: 1000}
			header := append([]byte(fmt.Sprintf("ssjack-key/v%d", version)), 0)
			header = append(header, []byte("argon2id-x4-hkdf-sha256")...)
			header = append(header, 0)
			for _, number := range []uint32{uint32(version), 1048576, 1, 1, 1000} {
				header = binary.BigEndian.AppendUint32(header, number)
			}
			var packet, combined []byte
			for i := 1; i <= 4; i++ {
				salt := bytes.Repeat([]byte{byte(i)}, 32)
				d.Salts = append(d.Salts, base64.StdEncoding.EncodeToString(salt))
				packet = append(packet, salt...)
				combined = append(combined, argon2.IDKey(password, salt, 1, 32, 1, 32)...)
			}
			nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
			d.Nonce = base64.StdEncoding.EncodeToString(nonce)
			packet = append(packet, nonce...)
			header = append(header, packet...)
			master := make([]byte, 32)
			if _, err := io.ReadFull(hkdf.New(sha256.New, combined, nil, []byte("ssjack-key/v1/master")), master); err != nil {
				t.Fatal(err)
			}
			defer clear(master)
			defer clear(combined)
			data := append([]byte(nil), payload...)
			if version == 2 {
				body, err := pure.EmitCanonical(map[string]any{
					"version": 2, "kdf": "argon2id-x4-hkdf-sha256", "memory_kib": 1048576,
					"passes": 1, "parallelism": 1, "layers": 1000, "cipher": "aes-256-gcm-hkdf-sha256",
					"purpose": "storage", "payload": base64.StdEncoding.EncodeToString(payload),
				})
				if err != nil {
					t.Fatal(err)
				}
				data = []byte(body)
			}
			for index := uint32(0); index < 1000; index++ {
				context := binary.BigEndian.AppendUint32([]byte(fmt.Sprintf("ssjack-key/v%d/storage/layer/", version)), index)
				key := make([]byte, 32)
				if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, context), key); err != nil {
					t.Fatal(err)
				}
				block, err := aes.NewCipher(key)
				clear(key)
				if err != nil {
					t.Fatal(err)
				}
				aead, err := cipher.NewGCM(block)
				if err != nil {
					t.Fatal(err)
				}
				n := append([]byte(nil), nonce...)
				binary.BigEndian.PutUint32(n[8:], binary.BigEndian.Uint32(nonce[8:])^index)
				aad := append(append([]byte(nil), header...), context...)
				data = aead.Seal(nil, n, data, aad)
			}
			var expected []byte
			if version == 2 {
				body, err := pure.EmitCanonical(map[string]any{"data": base64.StdEncoding.EncodeToString(append(packet, data...))})
				if err != nil {
					t.Fatal(err)
				}
				expected = []byte(body)
			} else {
				body, err := pure.EmitCanonical(map[string]any{
					"version": 1, "kdf": d.KDF, "memory_kib": 1048576, "passes": 1,
					"parallelism": 1, "layers": 1000, "salts": d.Salts, "nonce": d.Nonce,
					"ciphertext": base64.StdEncoding.EncodeToString(data),
				})
				if err != nil {
					t.Fatal(err)
				}
				expected = append([]byte("# ssjack encrypted key v1\n"), []byte(body)...)
			}
			actual, err := sealDocument(d, payload, password, testDerive)
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatalf("independent v%d vector mismatch: %v", version, err)
			}
			opened, err := open(expected, password, testDerive)
			if err != nil || !bytes.Equal(opened, payload) {
				t.Fatalf("independent vector read: %v", err)
			}
		})
	}
}
