package appstoreanchorrequest_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
)

func checkWire(t *testing.T, r appstoreanchorrequest.Request, want []byte) {
	t.Helper()
	if !r.Valid() || !bytes.Equal(r.Bytes(), want) {
		t.Fatal("independent canonical request bytes mismatch")
	}
	copied := r.Bytes()
	clear(copied)
	if !bytes.Equal(r.Bytes(), want) {
		t.Fatal("request bytes alias caller")
	}
}

func TestIndependentReadAndCreateVectors(t *testing.T) {
	store, rid := id(1), id(2)
	read, err := appstoreanchorrequest.NewRead(store, rid)
	if err != nil || read.Operation() != 1 || read.StoreID() != store || read.RequestID() != rid {
		t.Fatalf("read metadata: %v", err)
	}
	checkWire(t, read, common(1, rid))
	store[0], rid[0] = 0, 0
	if read.StoreID() != id(1) || read.RequestID() != id(2) {
		t.Fatal("read aliases input identities")
	}
	if _, present := read.ProposedState(); present {
		t.Fatal("read exposed a proposed mutation")
	}
	if _, present := read.IdempotencyKey(); present {
		t.Fatal("read exposed a mutation key")
	}
	if _, present := read.ExpectedStateHash(); present {
		t.Fatal("read exposed a CAS expectation")
	}

	create, err := appstoreanchorrequest.NewCreate(id(1))
	if err != nil {
		t.Fatal(err)
	}
	store = id(1)
	genesis := genesisWire()
	key := sum("SSAPP-CREATE-v1", store[:], genesis)
	want := mutationWire(2, "SSAPP-CREATE-REQUEST-ID-v1", genesis, [32]byte{}, key)
	checkWire(t, create, want)
	if len(want) != 272 || create.RequestID() != requestID("SSAPP-CREATE-REQUEST-ID-v1", key) {
		t.Fatal("create layout/ID")
	}
	gotKey, present := create.IdempotencyKey()
	if !present || gotKey != key {
		t.Fatal("create key")
	}
	proposed, present := create.ProposedState()
	pb := proposed.Bytes()
	if !present || !bytes.Equal(pb[:], genesis) {
		t.Fatal("create is not exact genesis")
	}
	if _, present := create.ExpectedStateHash(); present {
		t.Fatal("create exposed CAS expectation")
	}
	again, err := appstoreanchorrequest.NewCreate(id(1))
	if err != nil || again != create {
		t.Fatal("create rebuild changed bytes or IDs")
	}
}

func TestIndependentReservationAndCommitVectors(t *testing.T) {
	store := id(1)
	genesis := genesisWire()
	previous := state(t, genesis)
	e := entry(t, 0, 3, 4)
	eraw := binary.BigEndian.AppendUint64(nil, 0)
	eraw = append(eraw, bytes.Repeat([]byte{3}, 16)...)
	eraw = append(eraw, bytes.Repeat([]byte{4}, 16)...)
	reservedBytes := append([]byte(nil), genesis...)
	head := sum("SSAPP-JOURNAL-ENTRY-v1", store[:], genesis[104:136], eraw)
	binary.BigEndian.PutUint64(reservedBytes[96:104], 1)
	copy(reservedBytes[104:136], head[:])
	reserveKey := sum("SSAPP-RESERVE-v1", store[:], eraw)
	oldHash := sum("SSAPP-ANCHOR-STATE-v1", genesis)
	wantReserve := mutationWire(3, "SSAPP-RESERVE-REQUEST-ID-v1", reservedBytes, oldHash, reserveKey)
	reservation, err := appstoreanchorrequest.PlanReservation(previous, e)
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, reservation, wantReserve)
	if len(wantReserve) != 304 || reservation.Operation() != 3 {
		t.Fatal("reservation layout")
	}
	gotExpected, present := reservation.ExpectedStateHash()
	if !present || gotExpected != oldHash {
		t.Fatal("reservation expected-state hash")
	}
	again, err := appstoreanchorrequest.PlanReservation(previous, e)
	if err != nil || again != reservation {
		t.Fatal("reservation rebuild changed bytes")
	}

	candidate := hash(7)
	commit, err := appstoreanchorrequest.PlanCommit(reservation, candidate)
	if err != nil {
		t.Fatal(err)
	}
	committedBytes := append([]byte(nil), reservedBytes...)
	binary.BigEndian.PutUint64(committedBytes[24:32], 1)
	copy(committedBytes[32:48], bytes.Repeat([]byte{3}, 16))
	copy(committedBytes[48:80], candidate[:])
	copy(committedBytes[80:96], bytes.Repeat([]byte{4}, 16))
	transaction := id(4)
	commitKey := sum("SSAPP-COMMIT-v1", store[:], transaction[:], candidate[:])
	reservedHash := sum("SSAPP-ANCHOR-STATE-v1", reservedBytes)
	wantCommit := mutationWire(3, "SSAPP-COMMIT-REQUEST-ID-v1", committedBytes, reservedHash, commitKey)
	checkWire(t, commit, wantCommit)
	gotKey, present := commit.IdempotencyKey()
	if !present || gotKey != commitKey {
		t.Fatal("commit idempotency key")
	}
	gotExpected, present = commit.ExpectedStateHash()
	if !present || gotExpected != reservedHash {
		t.Fatal("commit expected-state hash")
	}
	if commit.RequestID() == requestID("SSAPP-RESERVE-REQUEST-ID-v1", commitKey) {
		t.Fatal("mutation request-ID domains were collapsed")
	}
	againCommit, err := appstoreanchorrequest.PlanCommit(again, candidate)
	if err != nil || againCommit != commit {
		t.Fatal("commit rebuild changed bytes or ID")
	}
	candidate[0] = 0
	returned, ok := commit.ProposedState()
	if !ok || returned.CommittedFileHash() != hash(7) {
		t.Fatal("commit aliases candidate hash")
	}
}
