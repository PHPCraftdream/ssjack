package appstoreheader_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	literal := "5353415050303031" + "0001" + "0000" +
		strings.Repeat("01", 16) + strings.Repeat("02", 16) + strings.Repeat("00", 16) +
		"00100000" + "0000000000100000" + "00000001" + "00000000" +
		strings.Repeat("11", 32) + strings.Repeat("22", 32) + strings.Repeat("33", 32) + strings.Repeat("44", 32) +
		strings.Repeat("55", 12)
	b, err := hex.DecodeString(literal)
	if err != nil || len(b) != 220 {
		t.Fatalf("independent fixture: %v, length %d", err, len(b))
	}
	return b
}

func reject(t *testing.T, raw []byte) {
	t.Helper()
	h, err := appstoreheader.Parse(raw)
	if !errors.Is(err, appstoreheader.ErrInvalid) || h != (appstoreheader.Header{}) {
		t.Fatalf("invalid framing exposed a header: %v", err)
	}
}

func TestLiteralHeaderAndOwnership(t *testing.T) {
	raw := fixture(t)
	h, err := appstoreheader.Parse(raw)
	if err != nil || !h.Valid() || h.PlaintextSize() != 1048576 || h.ChunkCount() != 1 || h.EncodedSize() != 1080868 {
		t.Fatalf("literal header: %v, sizes %d/%d/%d", err, h.PlaintextSize(), h.ChunkCount(), h.EncodedSize())
	}
	encoded := h.Bytes()
	if !bytes.Equal(encoded[:], raw) {
		t.Fatal("public bytes changed")
	}
	store, snapshot, parent, nonce, salts := h.StoreID(), h.SnapshotID(), h.ParentID(), h.NonceBase(), h.Salts()
	if store != [16]byte(bytes.Repeat([]byte{1}, 16)) || snapshot != [16]byte(bytes.Repeat([]byte{2}, 16)) || parent != ([16]byte{}) || nonce != [12]byte(bytes.Repeat([]byte{0x55}, 12)) {
		t.Fatal("identity or nonce offsets")
	}
	for i, value := range []byte{0x11, 0x22, 0x33, 0x44} {
		if salts[i] != [32]byte(bytes.Repeat([]byte{value}, 32)) {
			t.Fatalf("salt offset %d", i)
		}
	}
	for i := range raw {
		raw[i] = 0xff
	}
	changed := h.Bytes()
	changed[0] = 0
	store[0], snapshot[0], parent[0], nonce[0], salts[0][0] = 0, 0, 1, 0, 0
	if h.Bytes() != encoded || h.StoreID()[0] != 1 || h.SnapshotID()[0] != 2 || h.ParentID()[0] != 0 || h.NonceBase()[0] != 0x55 || h.Salts()[0][0] != 0x11 {
		t.Fatal("header aliases caller or accessor arrays")
	}
	var zero appstoreheader.Header
	if zero.Valid() || zero.EncodedSize() != 0 || zero.PlaintextSize() != 0 || zero.ChunkCount() != 0 {
		t.Fatal("zero header claims admission")
	}
}

func TestFieldRejections(t *testing.T) {
	for _, size := range []int{0, 1, 219, 221} {
		reject(t, make([]byte, size))
	}
	for i := 0; i < 8; i++ {
		raw := fixture(t)
		raw[i] ^= 0xff
		reject(t, raw)
	}
	for _, pair := range []struct {
		offset int
		value  uint16
	}{{8, 0}, {8, 2}, {8, 256}, {10, 1}, {10, 65535}} {
		raw := fixture(t)
		binary.BigEndian.PutUint16(raw[pair.offset:pair.offset+2], pair.value)
		reject(t, raw)
	}
	for _, pair := range []struct {
		offset int
		value  uint32
	}{
		{60, 0}, {60, 1048575}, {60, 1048577}, {60, ^uint32(0)},
		{72, 0}, {72, 2}, {72, 1048577}, {72, ^uint32(0)}, {76, 1}, {76, ^uint32(0)},
	} {
		raw := fixture(t)
		binary.BigEndian.PutUint32(raw[pair.offset:pair.offset+4], pair.value)
		reject(t, raw)
	}
	for _, plain := range []uint64{0, 1, 1048575, 1099511627777, ^uint64(0)} {
		raw := fixture(t)
		binary.BigEndian.PutUint64(raw[64:72], plain)
		reject(t, raw)
	}
	for _, span := range [][2]int{{12, 28}, {28, 44}, {80, 112}, {112, 144}, {144, 176}, {176, 208}, {208, 220}} {
		raw := fixture(t)
		clear(raw[span[0]:span[1]])
		reject(t, raw)
	}
	for i := 0; i < 4; i++ {
		for j := i + 1; j < 4; j++ {
			raw := fixture(t)
			copy(raw[80+j*32:112+j*32], raw[80+i*32:112+i*32])
			reject(t, raw)
		}
	}
	raw := fixture(t)
	reject(t, append(raw, 0))
}

func TestSizeBoundaries(t *testing.T) {
	for _, row := range []struct {
		plain   uint64
		chunks  uint32
		encoded uint64
	}{
		{1048576, 1, 1080868},
		{1048577, 2, 1096881},
		{2097151, 2, 2145455},
		{2097152, 2, 2145456},
		{1099511627776, 1048576, 1116301442968},
	} {
		t.Run(fmt.Sprint(row.plain), func(t *testing.T) {
			raw := fixture(t)
			binary.BigEndian.PutUint64(raw[64:72], row.plain)
			binary.BigEndian.PutUint32(raw[72:76], row.chunks)
			h, err := appstoreheader.Parse(raw)
			if err != nil || h.PlaintextSize() != row.plain || h.ChunkCount() != row.chunks || h.EncodedSize() != row.encoded {
				t.Fatalf("size boundary: %v, encoded %d instead of %d", err, h.EncodedSize(), row.encoded)
			}
			binary.BigEndian.PutUint32(raw[72:76], row.chunks-1)
			reject(t, raw)
			binary.BigEndian.PutUint32(raw[72:76], row.chunks+1)
			reject(t, raw)
		})
	}
	// Any nonzero parent is public metadata, not evidence of an anchored parent.
	raw := fixture(t)
	copy(raw[44:60], bytes.Repeat([]byte{3}, 16))
	if _, err := appstoreheader.Parse(raw); err != nil {
		t.Fatalf("non-genesis parent: %v", err)
	}
	// Public fields need not have every byte set; only the all-zero values reject.
	for _, span := range [][2]int{{12, 28}, {28, 44}, {80, 112}, {112, 144}, {144, 176}, {176, 208}, {208, 220}} {
		raw := fixture(t)
		clear(raw[span[0]:span[1]])
		raw[span[1]-1] = byte(span[0])
		if _, err := appstoreheader.Parse(raw); err != nil {
			t.Fatalf("nonzero field at %d: %v", span[0], err)
		}
	}
}
