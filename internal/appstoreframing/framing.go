// Package appstoreframing checks ciphertext structure, not authentication.
package appstoreframing

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

var ErrInvalid = errors.New("invalid application-store ciphertext framing")
var ErrUnavailable = errors.New("application-store framing read unavailable")

type Info struct {
	header     appstoreheader.Header
	transcript [32]byte
	framed     bool
}

// Inspect consumes exactly one snapshot without retaining or releasing its bodies.
func Inspect(r io.Reader) (Info, error) {
	if r == nil {
		return Info{}, ErrUnavailable
	}
	var raw [appstoreheader.Size]byte
	if err := readExact(r, raw[:]); err != nil {
		return Info{}, err
	}
	header, err := appstoreheader.Parse(raw[:])
	if err != nil {
		return Info{}, ErrInvalid
	}
	buffer := make([]byte, 32768)
	defer clear(buffer)
	digest := sha256.New()
	for index := uint32(0); index < header.ChunkCount(); index++ {
		var prefix [12]byte
		if err := readExact(r, prefix[:]); err != nil {
			return Info{}, err
		}
		plain := header.PlaintextSize() - uint64(index)*appstoreheader.ChunkSize
		if plain > appstoreheader.ChunkSize {
			plain = appstoreheader.ChunkSize
		}
		ciphertext := uint32(plain + 16000)
		if binary.BigEndian.Uint32(prefix[:4]) != index || binary.BigEndian.Uint32(prefix[4:8]) != uint32(plain) || binary.BigEndian.Uint32(prefix[8:12]) != ciphertext {
			return Info{}, ErrInvalid
		}
		_, _ = digest.Write(prefix[:])
		if err := consume(r, ciphertext, digest, buffer); err != nil {
			return Info{}, err
		}
	}
	var final [12]byte
	if err := readExact(r, final[:]); err != nil {
		return Info{}, err
	}
	if string(final[:4]) != "FIN1" || binary.BigEndian.Uint64(final[4:]) != 16048 {
		return Info{}, ErrInvalid
	}
	if err := consume(r, 16048, nil, buffer); err != nil {
		return Info{}, err
	}
	var extra [1]byte
	n, err := r.Read(extra[:])
	if n > 0 {
		return Info{}, ErrInvalid
	}
	if n != 0 || !errors.Is(err, io.EOF) {
		return Info{}, ErrUnavailable
	}
	info := Info{header: header, framed: true}
	copy(info.transcript[:], digest.Sum(nil))
	return info, nil
}

func consume(r io.Reader, remaining uint32, digest hash.Hash, buffer []byte) error {
	for remaining > 0 {
		n := len(buffer)
		if uint32(n) > remaining {
			n = int(remaining)
		}
		if err := readExact(r, buffer[:n]); err != nil {
			return err
		}
		if digest != nil {
			_, _ = digest.Write(buffer[:n])
		}
		remaining -= uint32(n)
	}
	return nil
}

func readExact(r io.Reader, b []byte) error {
	for offset := 0; offset < len(b); {
		n, err := r.Read(b[offset:])
		if n < 0 || n > len(b)-offset {
			return ErrUnavailable
		}
		offset += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				if offset == len(b) {
					return nil
				}
				return ErrInvalid
			}
			return ErrUnavailable
		}
		if n == 0 {
			return ErrUnavailable
		}
	}
	return nil
}

// Valid reports framing only, never successful AEAD or anchor verification.
func (i Info) Valid() bool                   { return i.framed }
func (i Info) Header() appstoreheader.Header { return i.header }
func (i Info) TranscriptHash() [32]byte      { return i.transcript }
