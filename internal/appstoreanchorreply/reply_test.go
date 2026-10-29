package appstoreanchorreply_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

func reject(t *testing.T, b []byte, public ed25519.PublicKey, expected appstoreanchorreply.Expected) {
	t.Helper()
	r, err := appstoreanchorreply.Verify(b, public, expected)
	if !errors.Is(err, appstoreanchorreply.ErrInvalid) || r != (appstoreanchorreply.Reply{}) {
		t.Fatalf("invalid reply exposed metadata: %v", err)
	}
}

func TestIndependentSignedOutcomes(t *testing.T) {
	cases := []struct {
		op      appstoreanchorreply.Operation
		outcome appstoreanchorreply.Outcome
		state   []byte
		version uint64
	}{
		{appstoreanchorreply.Read, appstoreanchorreply.ReadState, stateWire(false), 0},
		{appstoreanchorreply.Read, appstoreanchorreply.ReadState, stateWire(true), 2},
		{appstoreanchorreply.Read, appstoreanchorreply.Rejected, nil, 2},
		{appstoreanchorreply.Read, appstoreanchorreply.Unknown, nil, 2},
		{appstoreanchorreply.Read, appstoreanchorreply.NotFound, nil, 0},
		{appstoreanchorreply.CreateIfAbsent, appstoreanchorreply.Committed, stateWire(false), 0},
		{appstoreanchorreply.CreateIfAbsent, appstoreanchorreply.Conflict, stateWire(true), 2},
		{appstoreanchorreply.CreateIfAbsent, appstoreanchorreply.Rejected, nil, 2},
		{appstoreanchorreply.CreateIfAbsent, appstoreanchorreply.Unknown, nil, 2},
		{appstoreanchorreply.CAS, appstoreanchorreply.Committed, stateWire(true), 2},
		{appstoreanchorreply.CAS, appstoreanchorreply.Conflict, stateWire(true), 2},
		{appstoreanchorreply.CAS, appstoreanchorreply.Rejected, nil, 2},
		{appstoreanchorreply.CAS, appstoreanchorreply.Unknown, nil, 2},
		{appstoreanchorreply.Read, appstoreanchorreply.ReadState, stateWire(true), ^uint64(0)},
	}
	for _, row := range cases {
		b, public, expected := wire(row.op, row.outcome, row.state, row.version)
		r, err := appstoreanchorreply.Verify(b, public, expected)
		if err != nil || !r.SignatureValid() || r.Operation() != row.op || r.Outcome() != row.outcome || r.RequestID() != id(1) || r.StoreID() != id(2) || r.ServiceVersion() != row.version {
			t.Fatalf("signed outcome %d/%d: %v", row.op, row.outcome, err)
		}
		s, present := r.State()
		if present != (len(row.state) != 0) {
			t.Fatal("state presence mismatch")
		}
		if present {
			got := s.Bytes()
			if !s.Valid() || !bytes.Equal(got[:], row.state) {
				t.Fatal("signed state bytes mismatch")
			}
		} else if s != (appstoreanchorstate.State{}) {
			t.Fatal("empty outcome exposed state")
		}
	}
}

func TestSignatureTamperingKeyAndOwnership(t *testing.T) {
	original, public, expected := wire(appstoreanchorreply.Read, appstoreanchorreply.ReadState, stateWire(true), 2)
	for i := range original {
		b := append([]byte(nil), original...)
		b[i] ^= 1
		reject(t, b, public, expected)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
	for _, key := range []ed25519.PublicKey{nil, make([]byte, 31), make([]byte, 32), make([]byte, 33), other} {
		reject(t, original, key, expected)
	}
	for _, b := range [][]byte{nil, original[:351], append(append([]byte(nil), original...), 0)} {
		reject(t, b, public, expected)
	}
	r, err := appstoreanchorreply.Verify(original, public, expected)
	if err != nil {
		t.Fatal(err)
	}
	clear(original)
	clear(public)
	request := r.RequestID()
	request[0] = 0
	s, ok := r.State()
	sb := s.Bytes()
	sb[8] = 0
	if !ok || !r.SignatureValid() || r.RequestID() != id(1) || r.StoreID() != id(2) || s.StoreID() != id(2) {
		t.Fatal("reply aliases caller/accessor data")
	}
	if (appstoreanchorreply.Reply{}).SignatureValid() {
		t.Fatal("zero reply claims signature validity")
	}
}

func TestExpectedCorrelationIsRequired(t *testing.T) {
	b, public, expected := wire(appstoreanchorreply.Read, appstoreanchorreply.Unknown, nil, 2)
	for _, field := range []int{0, 1, 2} {
		wrong := expected
		if field == 0 {
			wrong.Operation = appstoreanchorreply.CAS
		}
		if field == 1 {
			wrong.RequestID[15] ^= 0x80
		}
		if field == 2 {
			wrong.StoreID[15] ^= 0x80
		}
		reject(t, b, public, wrong)
	}
	for _, op := range []appstoreanchorreply.Operation{0, 4} {
		raw, public, wrong := wire(op, appstoreanchorreply.Unknown, nil, 0)
		reject(t, raw, public, wrong)
	}
	for _, offset := range []int{16, 32} {
		raw := append([]byte(nil), b...)
		wrong := expected
		clear(raw[offset : offset+16])
		if offset == 16 {
			wrong.RequestID = [16]byte{}
		} else {
			wrong.StoreID = [16]byte{}
		}
		sign(raw)
		reject(t, raw, public, wrong)
	}
}
