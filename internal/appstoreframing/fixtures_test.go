package appstoreframing_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

type wire struct {
	data       []byte
	prefixes   []int
	bodies     []int
	final      int
	transcript [32]byte
}

func header(t *testing.T, plain uint64) []byte {
	t.Helper()
	literal := "535341505030303100010000" + strings.Repeat("01", 16) + strings.Repeat("02", 16) + strings.Repeat("00", 16) +
		"0010000000000000001000000000000100000000" +
		strings.Repeat("11", 32) + strings.Repeat("22", 32) + strings.Repeat("33", 32) + strings.Repeat("44", 32) + strings.Repeat("55", 12)
	b, err := hex.DecodeString(literal)
	if err != nil || len(b) != 220 {
		t.Fatal("invalid independent public header fixture")
	}
	binary.BigEndian.PutUint64(b[64:72], plain)
	binary.BigEndian.PutUint32(b[72:76], uint32((plain+1048575)/1048576))
	return b
}

// Bodies are synthetic ciphertext-shaped bytes, not authenticated encrypted data.
func fixture(t *testing.T, plain uint64) wire {
	t.Helper()
	if plain < 1048576 || plain > 2097152 {
		t.Fatal("fixture refuses payload-sized allocation beyond two chunks")
	}
	w := wire{data: header(t, plain)}
	remaining := plain
	for index := uint32(0); remaining != 0; index++ {
		n := remaining
		if n > 1048576 {
			n = 1048576
		}
		w.prefixes = append(w.prefixes, len(w.data))
		w.data = binary.BigEndian.AppendUint32(w.data, index)
		w.data = binary.BigEndian.AppendUint32(w.data, uint32(n))
		w.data = binary.BigEndian.AppendUint32(w.data, uint32(n+16000))
		w.bodies = append(w.bodies, len(w.data))
		w.data = append(w.data, bytes.Repeat([]byte{0xa0 + byte(index)}, int(n+16000))...)
		remaining -= n
	}
	w.final = len(w.data)
	w.transcript = sha256.Sum256(w.data[220:w.final])
	w.data = append(w.data, "FIN1"...)
	w.data = binary.BigEndian.AppendUint64(w.data, 16048)
	w.data = append(w.data, bytes.Repeat([]byte{0xee}, 16048)...)
	return w
}
