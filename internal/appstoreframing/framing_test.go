package appstoreframing_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreframing"
)

func reject(t *testing.T, reader io.Reader, want error) {
	t.Helper()
	info, err := appstoreframing.Inspect(reader)
	if !errors.Is(err, want) || info != (appstoreframing.Info{}) {
		t.Fatalf("failure exposed partial framing metadata: %v", err)
	}
}

func TestCompleteWireAndIndependentTranscript(t *testing.T) {
	for _, plain := range []uint64{1048576, 1048577, 1048593, 2097152} {
		t.Run(fmt.Sprint(plain), func(t *testing.T) {
			w := fixture(t, plain)
			info, err := appstoreframing.Inspect(bytes.NewReader(w.data))
			if err != nil || !info.Valid() || info.Header().PlaintextSize() != plain || info.Header().EncodedSize() != uint64(len(w.data)) || info.TranscriptHash() != w.transcript {
				t.Fatalf("independent wire/transcript mismatch: %v", err)
			}
			clear(w.data)
			hash := info.TranscriptHash()
			hash[0] ^= 1
			header := info.Header().Bytes()
			header[12] = 0
			if info.Header().StoreID()[0] != 1 || info.TranscriptHash() != w.transcript {
				t.Fatal("framing metadata aliases caller or accessors")
			}
		})
	}
	if (appstoreframing.Info{}).Valid() {
		t.Fatal("zero info claims framing admission")
	}
}

func TestChunkAndFinalPrefixRejections(t *testing.T) {
	w := fixture(t, 1048593)
	for name, mutate := range map[string]func([]byte){
		"index-start":          func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[0]:], 1) },
		"duplicate-index":      func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[1]:], 0) },
		"skipped-index":        func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[1]:], 2) },
		"reserved-index":       func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[0]:], ^uint32(0)) },
		"zero-plain":           func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[0]+4:], 0) },
		"short-full-chunk":     func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[0]+4:], 1048575) },
		"wrong-residual":       func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[1]+4:], 18) },
		"short-cipher":         func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[0]+8:], 1064575) },
		"huge-cipher":          func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[0]+8:], ^uint32(0)) },
		"zero-residual-cipher": func(b []byte) { binary.BigEndian.PutUint32(b[w.prefixes[1]+8:], 0) },
		"final-magic":          func(b []byte) { b[w.final] = 'X' },
		"short-final":          func(b []byte) { binary.BigEndian.PutUint64(b[w.final+4:], 16047) },
		"long-final":           func(b []byte) { binary.BigEndian.PutUint64(b[w.final+4:], 16049) },
		"huge-final":           func(b []byte) { binary.BigEndian.PutUint64(b[w.final+4:], ^uint64(0)) },
	} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte(nil), w.data...)
			mutate(b)
			reject(t, bytes.NewReader(b), appstoreframing.ErrInvalid)
		})
	}
}

func TestTruncationAndTrailingBytes(t *testing.T) {
	w := fixture(t, 1048593)
	for _, end := range []int{0, 219, 231, w.bodies[0] + 1, w.prefixes[1] - 1, w.prefixes[1] + 11, w.final - 1, w.final + 11, len(w.data) - 1} {
		t.Run(fmt.Sprint(end), func(t *testing.T) {
			reject(t, bytes.NewReader(w.data[:end]), appstoreframing.ErrInvalid)
		})
	}
	reject(t, bytes.NewReader(append(append([]byte(nil), w.data...), 0)), appstoreframing.ErrInvalid)
}

func TestFramingIsNotAuthentication(t *testing.T) {
	w := fixture(t, 1048576)
	for _, offset := range []int{12, w.final + 12} {
		b := append([]byte(nil), w.data...)
		b[offset] ^= 1
		info, err := appstoreframing.Inspect(bytes.NewReader(b))
		if err != nil || !info.Valid() || info.TranscriptHash() != w.transcript {
			t.Fatalf("header/final body must be excluded from the chunk transcript: %v", err)
		}
	}
	b := append([]byte(nil), w.data...)
	b[w.bodies[0]] ^= 1
	info, err := appstoreframing.Inspect(bytes.NewReader(b))
	if err != nil || !info.Valid() || info.TranscriptHash() == w.transcript {
		t.Fatalf("framing must hash changed ciphertext, not claim to authenticate it: %v", err)
	}
}
