package appstorecatalog_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
)

func TestEmptyObjectsAndExactPartition(t *testing.T) {
	h, b := fixture(t, 0)
	c, err := appstorecatalog.Parse(h, b)
	if err != nil || !c.Valid() || len(c.Entries()) != 0 || c.PayloadSize() != 0 {
		t.Fatalf("empty catalog: %v", err)
	}
	h, b = fixture(t, 1)
	reject(t, h, b)
	h, b = fixture(t, 5, row{1, 1, 0, 0, "bin"}, row{2, 1, 5, 0, "bin"}, row{3, 1, 0, 5, "bin"})
	c, err = appstorecatalog.Parse(h, b)
	if err != nil || len(c.Entries()) != 3 || c.Entries()[2].Offset() != 5 {
		t.Fatalf("empty entries at beginning/end, with version reused across distinct objects: %v", err)
	}
	binary.BigEndian.PutUint64(b[212:220], 4)
	reject(t, h, b)
}

func TestMaximumObjectAndEntryCount(t *testing.T) {
	const payload = uint64(1099510579200)
	h, b := fixture(t, payload, row{1, 1, payload, 0, "bin"})
	c, err := appstorecatalog.Parse(h, b)
	if err != nil || c.PayloadSize() != payload || c.Entries()[0].Length() != payload {
		t.Fatalf("maximum payload metadata without payload allocation: %v", err)
	}

	h, b = fixture(t, 0)
	binary.BigEndian.PutUint32(b[40:44], 16383)
	for i := 0; i < 16383; i++ {
		entry := b[44+i*64 : 108+i*64]
		binary.BigEndian.PutUint32(entry[12:16], uint32(i+1))
		copy(entry[16:32], bytes.Repeat([]byte{1}, 16))
		copy(entry[48:64], "bin")
	}
	c, err = appstorecatalog.Parse(h, b)
	if err != nil || len(c.Entries()) != 16383 {
		t.Fatalf("maximum catalog count: %v", err)
	}
	entries := c.Entries()
	first, last := entries[0].ObjectID(), entries[len(entries)-1].ObjectID()
	if binary.BigEndian.Uint32(first[12:16]) != 1 || binary.BigEndian.Uint32(last[12:16]) != 16383 {
		t.Fatal("maximum catalog identities changed")
	}
	b[44+16383*64] = 1
	reject(t, h, b)
	b[44+16383*64] = 0
	binary.BigEndian.PutUint32(b[40:44], 16384)
	reject(t, h, b)
}
