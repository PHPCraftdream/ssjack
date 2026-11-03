package appstoreanchorresult_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func id(value byte) [16]byte { return [16]byte(bytes.Repeat([]byte{value}, 16)) }

func requests(t *testing.T) (appstoreanchorstate.State, appstoreanchorrequest.Request, appstoreanchorrequest.Request, appstoreanchorrequest.Request) {
	t.Helper()
	g, err := appstoreanchorstate.Genesis(id(1))
	if err != nil {
		t.Fatal(err)
	}
	e, err := appstorejournal.NewEntry(0, id(3), id(4))
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := appstoreanchorrequest.PlanReservation(g, e)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := appstoreanchorrequest.PlanCommit(reserve, [32]byte(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	create, err := appstoreanchorrequest.NewCreate(id(1))
	if err != nil {
		t.Fatal(err)
	}
	return g, reserve, commit, create
}

func reply(t *testing.T, request appstoreanchorrequest.Request, outcome appstoreanchorreply.Outcome, state appstoreanchorstate.State, version uint64) appstoreanchorreply.Reply {
	t.Helper()
	return signed(t, appstoreanchorreply.Expected{Operation: appstoreanchorreply.Operation(request.Operation()), RequestID: request.RequestID(), StoreID: request.StoreID()}, outcome, state, version)
}

func signed(t *testing.T, expected appstoreanchorreply.Expected, outcome appstoreanchorreply.Outcome, state appstoreanchorstate.State, version uint64) appstoreanchorreply.Reply {
	t.Helper()
	b := make([]byte, 352)
	copy(b[:8], "SSASRSP1")
	b[8], b[9] = byte(expected.Operation), byte(outcome)
	rid, store := expected.RequestID, expected.StoreID
	copy(b[16:32], rid[:])
	copy(b[32:48], store[:])
	binary.BigEndian.PutUint64(b[48:56], version)
	if state.Valid() {
		raw := state.Bytes()
		binary.BigEndian.PutUint16(b[56:58], 192)
		copy(b[64:256], raw[:])
		hash := sha256.Sum256(append([]byte("SSAPP-ANCHOR-STATE-v1"), raw[:]...))
		copy(b[256:288], hash[:])
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	copy(b[288:352], ed25519.Sign(private, b[:288]))
	r, err := appstoreanchorreply.Verify(b, private.Public().(ed25519.PublicKey), expected)
	if err != nil {
		t.Fatalf("independent signed fixture: %v", err)
	}
	return r
}
