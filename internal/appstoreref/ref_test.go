package appstoreref_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func id(value byte) [16]byte { return [16]byte(bytes.Repeat([]byte{value}, 16)) }

func catalog(t *testing.T, empty bool) appstorecatalog.Catalog {
	t.Helper()
	literal := "535341505030303100010000" + strings.Repeat("01", 16) + strings.Repeat("02", 16) + strings.Repeat("00", 16) +
		"0010000000000000001000000000000100000000" +
		strings.Repeat("11", 32) + strings.Repeat("22", 32) + strings.Repeat("33", 32) + strings.Repeat("44", 32) + strings.Repeat("55", 12)
	hb, err := hex.DecodeString(literal)
	if err != nil || len(hb) != 220 {
		t.Fatal("invalid independent header fixture")
	}
	h, err := appstoreheader.Parse(hb)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1048576)
	copy(b[:8], "SSCAT001")
	copy(b[8:24], bytes.Repeat([]byte{1}, 16))
	copy(b[24:40], bytes.Repeat([]byte{2}, 16))
	if !empty {
		binary.BigEndian.PutUint32(b[40:44], 3)
		for i, row := range []struct {
			object, version byte
			media           string
		}{{3, 4, "bin"}, {3, 5, "json"}, {6, 4, "txt"}} {
			entry := b[44+i*64 : 108+i*64]
			copy(entry[:16], bytes.Repeat([]byte{row.object}, 16))
			copy(entry[16:32], bytes.Repeat([]byte{row.version}, 16))
			copy(entry[48:64], row.media)
		}
	}
	c, err := appstorecatalog.Parse(h, b)
	if err != nil {
		t.Fatal(err)
	}
	clear(b)
	return c
}

func reference(t *testing.T, store, object, version, snapshot [16]byte) appstoreref.Ref {
	t.Helper()
	r, err := appstoreref.New(store, object, version, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTupleAndCopyOwnership(t *testing.T) {
	store, object, version, snapshot := id(1), id(3), id(4), id(2)
	r := reference(t, store, object, version, snapshot)
	if !r.Valid() || r.StoreID() != id(1) || r.ObjectID() != id(3) || r.VersionID() != id(4) || r.SnapshotID() != id(2) {
		t.Fatal("reference tuple order")
	}
	store[0], object[0], version[0], snapshot[0] = 0, 0, 0, 0
	returned := r.ObjectID()
	returned[0] = 0
	if r.StoreID() != id(1) || r.ObjectID() != id(3) || r.VersionID() != id(4) || r.SnapshotID() != id(2) {
		t.Fatal("reference aliases caller or getter arrays")
	}
	if (appstoreref.Ref{}).Valid() {
		t.Fatal("zero reference admitted")
	}
}

func TestAllIDsAreRequired(t *testing.T) {
	for index := 0; index < 4; index++ {
		ids := [4][16]byte{id(1), id(3), id(4), id(2)}
		ids[index] = [16]byte{}
		r, err := appstoreref.New(ids[0], ids[1], ids[2], ids[3])
		if !errors.Is(err, appstoreref.ErrInvalid) || r != (appstoreref.Ref{}) {
			t.Fatalf("missing ID %d admitted or leaked: %v", index, err)
		}
	}
	var nonzero [16]byte
	nonzero[15] = 1
	r := reference(t, nonzero, nonzero, nonzero, nonzero)
	if !r.Valid() {
		t.Fatal("nonzero boundary rejected")
	}
}

func TestExactVersionMetadata(t *testing.T) {
	c := catalog(t, false)
	for _, row := range []struct {
		object, version byte
		media           string
	}{{3, 4, "bin"}, {3, 5, "json"}, {6, 4, "txt"}} {
		r := reference(t, id(1), id(row.object), id(row.version), id(2))
		entry, err := appstoreref.FindMetadata(r, c)
		if err != nil || entry.ObjectID() != id(row.object) || entry.VersionID() != id(row.version) || entry.MediaType() != row.media {
			t.Fatalf("exact metadata pair %d/%d: %v", row.object, row.version, err)
		}
	}
	// A well-formed tuple is neither membership nor permission to obtain bytes.
	r := reference(t, id(1), id(3), id(6), id(2))
	if !r.Valid() {
		t.Fatal("absent reference should still be structurally valid")
	}
	entry, err := appstoreref.FindMetadata(r, c)
	if !errors.Is(err, appstoreref.ErrNotFound) || entry != (appstorecatalog.Entry{}) {
		t.Fatal("missing version fell back to another version")
	}
}

func TestNoScopeOrIdentityFallback(t *testing.T) {
	c := catalog(t, false)
	cases := []struct {
		store, object, version, snapshot [16]byte
		want                             error
	}{
		{id(9), id(3), id(4), id(2), appstoreref.ErrScope},
		{id(1), id(3), id(4), id(9), appstoreref.ErrScope},
		{id(1), id(9), id(4), id(2), appstoreref.ErrNotFound},
		{id(1), id(4), id(3), id(2), appstoreref.ErrNotFound},
		{id(1), id(3), id(9), id(2), appstoreref.ErrNotFound},
	}
	for field := 0; field < 4; field++ {
		ids := [4][16]byte{id(1), id(3), id(4), id(2)}
		ids[field][15] ^= 0x80
		want := appstoreref.ErrNotFound
		if field == 0 || field == 3 {
			want = appstoreref.ErrScope
		}
		cases = append(cases, struct {
			store, object, version, snapshot [16]byte
			want                             error
		}{ids[0], ids[1], ids[2], ids[3], want})
	}
	for _, row := range cases {
		r := reference(t, row.store, row.object, row.version, row.snapshot)
		entry, err := appstoreref.FindMetadata(r, c)
		if !errors.Is(err, row.want) || entry != (appstorecatalog.Entry{}) {
			t.Fatalf("scope/identity fallback: %v", err)
		}
	}
}

func TestInvalidAndEmptyCatalogs(t *testing.T) {
	r := reference(t, id(1), id(3), id(4), id(2))
	for _, row := range []struct {
		ref     appstoreref.Ref
		catalog appstorecatalog.Catalog
		want    error
	}{
		{appstoreref.Ref{}, catalog(t, false), appstoreref.ErrInvalid},
		{r, appstorecatalog.Catalog{}, appstoreref.ErrInvalid},
		{r, catalog(t, true), appstoreref.ErrNotFound},
	} {
		entry, err := appstoreref.FindMetadata(row.ref, row.catalog)
		if !errors.Is(err, row.want) || entry != (appstorecatalog.Entry{}) {
			t.Fatalf("invalid/empty metadata exposed an entry: %v", err)
		}
	}
}
