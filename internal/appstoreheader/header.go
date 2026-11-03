// Package appstoreheader checks public framing without authenticating snapshots.
package appstoreheader

import (
	"encoding/binary"
	"errors"
)

const (
	Size         = 220
	ChunkSize    = 1 << 20
	MaxPlaintext = 1 << 40
	MaxChunks    = 1 << 20
)

var ErrInvalid = errors.New("invalid application-store public header")

type Header struct {
	raw     [Size]byte
	plain   uint64
	chunks  uint32
	encoded uint64
	parsed  bool
}

// Parse accepts exactly one header, never ciphertext or a whole snapshot.
func Parse(raw []byte) (Header, error) {
	if len(raw) != Size {
		return Header{}, ErrInvalid
	}
	var h Header
	copy(h.raw[:], raw)
	b := h.raw[:]
	if string(b[:8]) != "SSAPP001" || binary.BigEndian.Uint16(b[8:10]) != 1 || binary.BigEndian.Uint16(b[10:12]) != 0 || binary.BigEndian.Uint32(b[60:64]) != ChunkSize || binary.BigEndian.Uint32(b[76:80]) != 0 {
		return Header{}, ErrInvalid
	}
	plain := binary.BigEndian.Uint64(b[64:72])
	chunks := binary.BigEndian.Uint32(b[72:76])
	if plain < ChunkSize || plain > MaxPlaintext || chunks == 0 || chunks > MaxChunks {
		return Header{}, ErrInvalid
	}
	if uint64(chunks) != (plain+ChunkSize-1)/ChunkSize {
		return Header{}, ErrInvalid
	}
	if zero(b[12:28]) || zero(b[28:44]) || zero(b[208:220]) {
		return Header{}, ErrInvalid
	}
	salts := h.Salts()
	for i := range salts {
		if zero(salts[i][:]) {
			return Header{}, ErrInvalid
		}
		for j := 0; j < i; j++ {
			if salts[i] == salts[j] {
				return Header{}, ErrInvalid
			}
		}
	}
	h.plain, h.chunks, h.parsed = plain, chunks, true
	// Validated caps keep every intermediate below 2^41, including all tags.
	h.encoded = Size + plain + uint64(chunks)*(12+16000) + 12 + 16048
	return h, nil
}

func zero(value []byte) bool {
	var bits byte
	for _, b := range value {
		bits |= b
	}
	return bits == 0
}

// Valid reports framing admission only; the zero value is invalid.
func (h Header) Valid() bool           { return h.parsed }
func (h Header) Bytes() [Size]byte     { return h.raw }
func (h Header) PlaintextSize() uint64 { return h.plain }
func (h Header) ChunkCount() uint32    { return h.chunks }
func (h Header) EncodedSize() uint64   { return h.encoded }
func (h Header) StoreID() [16]byte     { return [16]byte(h.raw[12:28]) }
func (h Header) SnapshotID() [16]byte  { return [16]byte(h.raw[28:44]) }
func (h Header) ParentID() [16]byte    { return [16]byte(h.raw[44:60]) }
func (h Header) NonceBase() [12]byte   { return [12]byte(h.raw[208:220]) }
func (h Header) Salts() [4][32]byte {
	var salts [4][32]byte
	for i := range salts {
		salts[i] = [32]byte(h.raw[80+i*32 : 112+i*32])
	}
	return salts
}
