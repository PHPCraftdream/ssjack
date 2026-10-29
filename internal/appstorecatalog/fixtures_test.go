package appstorecatalog_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

type row struct {
	object, version byte
	length, offset  uint64
	media           string
}

func fixture(t *testing.T, payload uint64, rows ...row) (appstoreheader.Header, []byte) {
	t.Helper()
	hexHeader := "535341505030303100010000" + strings.Repeat("01", 16) + strings.Repeat("02", 16) + strings.Repeat("00", 16) +
		"0010000000000000001000000000000100000000" +
		strings.Repeat("11", 32) + strings.Repeat("22", 32) + strings.Repeat("33", 32) + strings.Repeat("44", 32) + strings.Repeat("55", 12)
	hb, err := hex.DecodeString(hexHeader)
	if err != nil || len(hb) != 220 {
		t.Fatal("invalid independent header fixture")
	}
	binary.BigEndian.PutUint64(hb[64:72], 1048576+payload)
	binary.BigEndian.PutUint32(hb[72:76], uint32((1048576+payload+1048575)/1048576))
	header, err := appstoreheader.Parse(hb)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1048576)
	copy(b[:8], "SSCAT001")
	copy(b[8:24], bytes.Repeat([]byte{1}, 16))
	copy(b[24:40], bytes.Repeat([]byte{2}, 16))
	binary.BigEndian.PutUint32(b[40:44], uint32(len(rows)))
	for i, row := range rows {
		entry := b[44+i*64 : 108+i*64]
		copy(entry[:16], bytes.Repeat([]byte{row.object}, 16))
		copy(entry[16:32], bytes.Repeat([]byte{row.version}, 16))
		binary.BigEndian.PutUint64(entry[32:40], row.length)
		binary.BigEndian.PutUint64(entry[40:48], row.offset)
		copy(entry[48:64], row.media)
	}
	return header, b
}

func valid(t *testing.T) (appstoreheader.Header, []byte) {
	t.Helper()
	return fixture(t, 5, row{3, 4, 0, 0, "bin"}, row{3, 5, 3, 0, "app/json"}, row{6, 7, 2, 3, "a+b/c-d"})
}

func reject(t *testing.T, header appstoreheader.Header, b []byte) {
	t.Helper()
	c, err := appstorecatalog.Parse(header, b)
	if !errors.Is(err, appstorecatalog.ErrInvalid) || c.Valid() || len(c.Entries()) != 0 || c.PayloadSize() != 0 || c.StoreID() != ([16]byte{}) || c.SnapshotID() != ([16]byte{}) {
		t.Fatalf("invalid catalog exposed metadata: %v", err)
	}
}
