package appstorecatalog_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

func TestCatalogMetadataAndOwnership(t *testing.T) {
	header, raw := valid(t)
	c, err := appstorecatalog.Parse(header, raw)
	if err != nil || !c.Valid() || c.PayloadSize() != 5 || c.StoreID() != header.StoreID() || c.SnapshotID() != header.SnapshotID() {
		t.Fatalf("catalog admission: %v", err)
	}
	entries := c.Entries()
	if len(entries) != 3 || entries[0].ObjectID() != [16]byte(bytes.Repeat([]byte{3}, 16)) || entries[0].VersionID() != [16]byte(bytes.Repeat([]byte{4}, 16)) {
		t.Fatal("entry identity or count")
	}
	for i, want := range []struct {
		length, offset uint64
		media          string
	}{{0, 0, "bin"}, {3, 0, "app/json"}, {2, 3, "a+b/c-d"}} {
		if entries[i].Length() != want.length || entries[i].Offset() != want.offset || entries[i].MediaType() != want.media {
			t.Fatalf("entry %d metadata", i)
		}
	}
	clear(raw)
	entries[0] = appstorecatalog.Entry{}
	id := c.Entries()[1].ObjectID()
	id[0] = 0
	if c.Entries()[0].ObjectID()[0] != 3 || c.Entries()[1].ObjectID()[0] != 3 || c.Entries()[1].MediaType() != "app/json" {
		t.Fatal("catalog aliases input or returned entries")
	}
	if (appstorecatalog.Catalog{}).Valid() {
		t.Fatal("zero catalog claims admission")
	}
}

func TestClosedCatalogFraming(t *testing.T) {
	header, raw := valid(t)
	reject(t, appstoreheader.Header{}, raw)
	for _, b := range [][]byte{nil, raw[:1048575], append(append([]byte(nil), raw...), 0)} {
		reject(t, header, b)
	}
	for i := 0; i < 8; i++ {
		h, b := valid(t)
		b[i] ^= 0xff
		reject(t, h, b)
	}
	for _, offset := range []int{8, 24} {
		h, b := valid(t)
		b[offset] ^= 0xff
		reject(t, h, b)
	}
	for _, count := range []uint32{0, 2, 4, 16384, ^uint32(0)} {
		h, b := valid(t)
		binary.BigEndian.PutUint32(b[40:44], count)
		reject(t, h, b)
	}
	for _, offset := range []int{44 + 3*64, 1048575} {
		h, b := valid(t)
		b[offset] = 1
		reject(t, h, b)
	}
}

func TestEntryRejections(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"object-zero":    func(b []byte) { clear(b[44:60]) },
		"version-zero":   func(b []byte) { clear(b[60:76]) },
		"duplicate-pair": func(b []byte) { copy(b[108:140], b[44:76]) },
		"descending-pairs": func(b []byte) {
			first := append([]byte(nil), b[44:76]...)
			copy(b[44:76], b[108:140])
			copy(b[108:140], first)
		},
		"empty-offset":     func(b []byte) { binary.BigEndian.PutUint64(b[84:92], 1) },
		"gap":              func(b []byte) { binary.BigEndian.PutUint64(b[148:156], 1) },
		"overlap":          func(b []byte) { binary.BigEndian.PutUint64(b[212:220], 2) },
		"oversize-offset":  func(b []byte) { binary.BigEndian.PutUint64(b[148:156], ^uint64(0)) },
		"oversize-length":  func(b []byte) { binary.BigEndian.PutUint64(b[140:148], ^uint64(0)) },
		"incomplete-cover": func(b []byte) { binary.BigEndian.PutUint64(b[204:212], 1) },
		"overrun":          func(b []byte) { binary.BigEndian.PutUint64(b[204:212], 3) },
	} {
		t.Run(name, func(t *testing.T) {
			h, b := valid(t)
			mutate(b)
			reject(t, h, b)
		})
	}
	// Naive uint64 summation would wrap these ordered spans back to payload size 1.
	h, b := fixture(t, 1, row{3, 4, ^uint64(0), 0, "bin"}, row{5, 6, 2, ^uint64(0), "bin"})
	reject(t, h, b)
}

func TestMediaEncoding(t *testing.T) {
	for _, media := range []string{"", "abcdefghijklmnop", "application/json", "BIN", "a_b", "a b", "/a", "a/", "a/b/c", "a//b", "a\x00b", "a\x7f", "é", "a;v=1"} {
		t.Run(fmt.Sprintf("invalid-%q", media), func(t *testing.T) {
			h, b := fixture(t, 1, row{3, 4, 1, 0, media})
			reject(t, h, b)
		})
	}
	for _, media := range []string{"a", "a/b", "abcdefghijklmno", "a+b/c-d", ".", "+", "-", "0/9"} {
		t.Run(fmt.Sprintf("valid-%q", media), func(t *testing.T) {
			h, b := fixture(t, 1, row{3, 4, 1, 0, media})
			c, err := appstorecatalog.Parse(h, b)
			if err != nil || c.Entries()[0].MediaType() != media {
				t.Fatalf("valid media rejected: %v", err)
			}
		})
	}
}
