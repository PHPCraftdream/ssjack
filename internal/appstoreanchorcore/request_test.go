package appstoreanchorcore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

func id(v byte) [16]byte   { return [16]byte(bytes.Repeat([]byte{v}, 16)) }
func hash(v byte) [32]byte { return [32]byte(bytes.Repeat([]byte{v}, 32)) }
func independent(domain string, parts ...[]byte) [32]byte {
	b := []byte(domain)
	for _, p := range parts {
		b = append(b, p...)
	}
	return sha256.Sum256(b)
}
func state(t *testing.T, sequence, count uint64) appstoreanchorstate.State {
	t.Helper()
	b := make([]byte, 192)
	copy(b[:4], "SSAS")
	binary.BigEndian.PutUint16(b[4:6], 1)
	store := id(1)
	copy(b[8:24], store[:])
	binary.BigEndian.PutUint64(b[24:32], sequence)
	if sequence > 0 {
		copy(b[32:48], bytes.Repeat([]byte{2}, 16))
		copy(b[48:80], bytes.Repeat([]byte{3}, 32))
		copy(b[80:96], bytes.Repeat([]byte{4}, 16))
	}
	binary.BigEndian.PutUint64(b[96:104], count)
	head := hash(9)
	copy(b[104:136], head[:])
	s, err := appstoreanchorstate.Parse(b, store)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func wire(kind Kind, before [32]byte, proposed appstoreanchorstate.State) []byte {
	size, op := 48, byte(1)
	if kind == Create {
		size, op = 272, 2
	} else if kind == Reserve || kind == Commit {
		size, op = 304, 3
	}
	b := make([]byte, size)
	copy(b[:8], "SSASREQ1")
	b[8] = op
	store, request := id(1), id(8)
	copy(b[16:32], store[:])
	copy(b[32:48], request[:])
	if kind == Read {
		return b
	}
	encoded := proposed.Bytes()
	key := hash(7)
	domain := "SSAPP-RESERVE-REQUEST-ID-v1"
	if kind == Create {
		copy(b[48:240], encoded[:])
		key = independent("SSAPP-CREATE-v1", store[:], encoded[:])
		domain = "SSAPP-CREATE-REQUEST-ID-v1"
	} else {
		copy(b[48:80], before[:])
		copy(b[80:272], encoded[:])
		if kind == Commit {
			txn, file := proposed.CommittedTransactionID(), proposed.CommittedFileHash()
			key = independent("SSAPP-COMMIT-v1", store[:], txn[:], file[:])
			domain = "SSAPP-COMMIT-REQUEST-ID-v1"
		}
	}
	copy(b[size-32:], key[:])
	digest := independent(domain, store[:], key[:])
	copy(b[32:48], digest[:16])
	return b
}
func parsed(t *testing.T, b []byte) Request {
	t.Helper()
	r, err := Parse(b, id(1))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestIndependentCanonicalRequestShapesAndOwnership(t *testing.T) {
	genesis, _ := appstoreanchorstate.Genesis(id(1))
	for _, kind := range []Kind{Read, Create, Reserve, Commit} {
		proposed := genesis
		if kind == Reserve {
			proposed = state(t, 0, 1)
		} else if kind == Commit {
			proposed = state(t, 1, 1)
		}
		b := wire(kind, hash(6), proposed)
		original := append([]byte(nil), b...)
		r := parsed(t, b)
		if !r.Valid() || r.Kind() != kind || r.StoreID() != id(1) || !bytes.Equal(r.Bytes(), original) {
			t.Fatal("request vector changed")
		}
		_, hasKey := r.Key()
		if hasKey != (kind != Read) {
			t.Fatal("wrong mutation key presence")
		}
		clear(b)
		returned := r.Bytes()
		clear(returned)
		if !bytes.Equal(r.Bytes(), original) {
			t.Fatal("request aliases caller/accessor")
		}
	}
	if (Request{}).Valid() {
		t.Fatal("zero request accepted")
	}
}

func TestRejectMalformedRequests(t *testing.T) {
	genesis, _ := appstoreanchorstate.Genesis(id(1))
	for _, length := range []int{0, 1, 47, 49, 271, 273, 303, 305} {
		if r, err := Parse(make([]byte, length), id(1)); err != ErrInvalid || r.Valid() {
			t.Fatal("wrong length accepted")
		}
	}
	for _, kind := range []Kind{Read, Create, Reserve, Commit} {
		proposed := genesis
		if kind == Reserve {
			proposed = state(t, 0, 1)
		} else if kind == Commit {
			proposed = state(t, 1, 1)
		}
		original := wire(kind, hash(6), proposed)
		for _, offset := range []int{0, 8, 9, 16, 32} {
			if kind == Read && offset == 32 {
				continue
			}
			b := append([]byte(nil), original...)
			b[offset] ^= 0xff
			if r, err := Parse(b, id(1)); err != ErrInvalid || r.Valid() {
				t.Fatalf("kind %d field %d accepted", kind, offset)
			}
		}
		b := append([]byte(nil), original...)
		clear(b[32:48])
		if _, err := Parse(b, id(1)); err != ErrInvalid {
			t.Fatal("zero request ID accepted")
		}
		if _, err := Parse(original, id(2)); err != ErrInvalid {
			t.Fatal("cross-store request accepted")
		}
		if _, err := Parse(original, [16]byte{}); err != ErrInvalid {
			t.Fatal("zero scope accepted")
		}
		if kind != Read {
			b = append([]byte(nil), original...)
			b[len(b)-1] ^= 1
			if _, err := Parse(b, id(1)); err != ErrInvalid {
				t.Fatal("key changed without ID change")
			}
		}
	}
	cas := wire(Commit, hash(6), state(t, 1, 1))
	clear(cas[48:80])
	if _, err := Parse(cas, id(1)); err != ErrInvalid {
		t.Fatal("zero expected hash accepted")
	}
	create := wire(Create, hash(6), state(t, 0, 1))
	if _, err := Parse(create, id(1)); err != ErrInvalid {
		t.Fatal("non-genesis create accepted")
	}
	commit := wire(Commit, hash(6), state(t, 1, 1))
	commit[303] ^= 1
	key := [32]byte(commit[272:304])
	store := id(1)
	request := independent("SSAPP-COMMIT-REQUEST-ID-v1", store[:], key[:])
	copy(commit[32:48], request[:16])
	if _, err := Parse(commit, id(1)); err != ErrInvalid {
		t.Fatal("correlated but wrong commit key accepted")
	}
}
