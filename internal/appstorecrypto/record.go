package appstorecrypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"golang.org/x/crypto/hkdf"
)

const recordLayers = 1000

var ErrRecord = errors.New("invalid application-store record context")
var ErrClosed = errors.New("application-store master closed or unavailable")
var ErrBusy = errors.New("application-store master operation busy")
var ErrAuthentication = errors.New("application-store record authentication failed")

// These primitives stay private until reservation and full-snapshot release gates exist.
func (m *Master) sealRecord(ctx context.Context, h appstoreheader.Header, index uint32, final bool, plaintext []byte) ([]byte, error) {
	return m.transformRecord(ctx, h, index, final, plaintext, true, nil)
}
func (m *Master) openRecord(ctx context.Context, h appstoreheader.Header, index uint32, final bool, ciphertext []byte) ([]byte, error) {
	return m.transformRecord(ctx, h, index, final, ciphertext, false, nil)
}

func recordLength(h appstoreheader.Header, index uint32, final bool) (int, error) {
	if !h.Valid() {
		return 0, ErrRecord
	}
	if final {
		if index != ^uint32(0) {
			return 0, ErrRecord
		}
		return 48, nil
	}
	if index >= h.ChunkCount() {
		return 0, ErrRecord
	}
	remaining := h.PlaintextSize() - uint64(index)*appstoreheader.ChunkSize
	if remaining > appstoreheader.ChunkSize {
		remaining = appstoreheader.ChunkSize
	}
	return int(remaining), nil
}

func finalPlain(h appstoreheader.Header, data []byte) bool {
	return len(data) == 48 && string(data[:4]) == "FIN1" && binary.BigEndian.Uint64(data[4:12]) == h.PlaintextSize() && binary.BigEndian.Uint32(data[12:16]) == h.ChunkCount()
}

func (m *Master) transformRecord(ctx context.Context, h appstoreheader.Header, index uint32, final bool, input []byte, sealing bool, observe func(uint32)) ([]byte, error) {
	plain, err := recordLength(h, index, final)
	if err != nil || ctx == nil {
		return nil, ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ciphertext := plain + recordLayers*16
	want := ciphertext
	if sealing {
		want = plain
	}
	if len(input) != want {
		return nil, ErrRecord
	}
	if m == nil || m.state == nil {
		return nil, ErrClosed
	}
	if !m.state.mu.TryLock() {
		return nil, ErrBusy
	}
	defer m.state.mu.Unlock()
	if !m.state.ready {
		return nil, ErrClosed
	}
	if m.state.store != h.StoreID() || m.state.salts != h.Salts() {
		return nil, ErrRecord
	}
	data := make([]byte, len(input), ciphertext)
	copy(data, input)
	complete := false
	defer func() {
		if !complete {
			clear(data[:cap(data)])
		}
	}()
	if sealing && final && !finalPlain(h, data) {
		return nil, ErrRecord
	}
	for step := 0; step < recordLayers; step++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		layer := uint32(step)
		if !sealing {
			layer = uint32(recordLayers - 1 - step)
		}
		aead, nonce, aad, err := recordLayer(m.state.key[:], h, index, layer, final, uint32(plain), uint32(ciphertext))
		if err != nil {
			return nil, ErrDerivation
		}
		if sealing {
			data = aead.Seal(data[:0], nonce[:], data, aad)
		} else {
			opened, err := aead.Open(data[:0], nonce[:], data, aad)
			if err != nil {
				return nil, ErrAuthentication
			}
			clear(data[len(opened):])
			data = opened
		}
		if observe != nil {
			observe(layer)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !sealing && final && !finalPlain(h, data) {
		return nil, ErrRecord
	}
	complete = true
	return data, nil
}

func recordLayer(master []byte, h appstoreheader.Header, index, layer uint32, final bool, plain, ciphertext uint32) (cipher.AEAD, [12]byte, []byte, error) {
	if len(master) != 32 || layer >= recordLayers {
		return nil, [12]byte{}, nil, ErrRecord
	}
	contextDomain, nonceDomain, label := "ssjack-appstore/v1/data/chunk/", "ssjack-appstore/v1/nonce", "SSAPP chunk layer"
	if final {
		contextDomain, nonceDomain, label = "ssjack-appstore/v1/data/final/", "ssjack-appstore/v1/nonce/final", "SSAPP final layer"
	}
	store, snapshot, base := h.StoreID(), h.SnapshotID(), h.NonceBase()
	contextBytes := append([]byte(contextDomain), store[:]...)
	contextBytes = append(contextBytes, snapshot[:]...)
	contextBytes = binary.BigEndian.AppendUint32(contextBytes, index)
	contextBytes = binary.BigEndian.AppendUint32(contextBytes, layer)
	var key [32]byte
	defer clear(key[:])
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, contextBytes), key[:]); err != nil {
		return nil, [12]byte{}, nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, [12]byte{}, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, [12]byte{}, nil, err
	}
	nonceInput := append([]byte(nonceDomain), store[:]...)
	nonceInput = append(nonceInput, snapshot[:]...)
	nonceInput = binary.BigEndian.AppendUint32(nonceInput, index)
	nonceInput = binary.BigEndian.AppendUint32(nonceInput, layer)
	mac := hmac.New(sha256.New, base[:])
	_, _ = mac.Write(nonceInput)
	nonceSum := mac.Sum(nil)
	var nonce [12]byte
	copy(nonce[:], nonceSum[:12])
	clear(nonceSum)
	header := h.Bytes()
	aad := append([]byte(nil), header[:]...)
	aad = binary.BigEndian.AppendUint32(aad, index)
	aad = binary.BigEndian.AppendUint32(aad, layer)
	aad = binary.BigEndian.AppendUint32(aad, plain)
	aad = binary.BigEndian.AppendUint32(aad, ciphertext)
	aad = append(aad, label...)
	return aead, nonce, aad, nil
}
