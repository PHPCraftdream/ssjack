package appstoreanchorrequest

import (
	"encoding/binary"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

// NewCreate prepares canonical genesis; it does not prove the store is absent.
func NewCreate(store [16]byte) (Request, error) {
	genesis, err := appstoreanchorstate.Genesis(store)
	if err != nil {
		return Request{}, ErrInvalid
	}
	stateBytes := genesis.Bytes()
	key := sum("SSAPP-CREATE-v1", store[:], stateBytes[:])
	return mutation(createKind, genesis, [32]byte{}, key, "SSAPP-CREATE-REQUEST-ID-v1")
}

// PlanReservation checks local shape only, not history, durability or CAS success.
func PlanReservation(previous appstoreanchorstate.State, entry appstorejournal.Entry) (Request, error) {
	if !previous.Valid() || !entry.Valid() || previous.JournalCount() >= appstoreanchorstate.MaxReservations || entry.Index() != previous.JournalCount() {
		return Request{}, ErrInvalid
	}
	if entry.SnapshotID() == previous.CommittedSnapshotID() || entry.TransactionID() == previous.CommittedTransactionID() {
		return Request{}, ErrInvalid
	}
	store := previous.StoreID()
	head, err := appstorejournal.NextHead(store, previous.JournalHead(), entry)
	if err != nil {
		return Request{}, ErrInvalid
	}
	raw := previous.Bytes()
	binary.BigEndian.PutUint64(raw[96:104], previous.JournalCount()+1)
	copy(raw[104:136], head[:])
	next, err := appstoreanchorstate.Parse(raw[:], store)
	if err != nil {
		return Request{}, ErrInvalid
	}
	entryBytes := entry.Bytes()
	key := sum("SSAPP-RESERVE-v1", store[:], entryBytes[:])
	r, err := mutation(reserveKind, next, previous.Hash(), key, "SSAPP-RESERVE-REQUEST-ID-v1")
	if err != nil {
		return Request{}, ErrInvalid
	}
	r.entry = entry
	return r, nil
}

// PlanCommit does not confirm reservation, candidate verification or durable intent.
func PlanCommit(reservation Request, candidateHash [32]byte) (Request, error) {
	if reservation.kind != reserveKind || !reservation.Valid() || !reservation.state.Valid() || !reservation.entry.Valid() || candidateHash == ([32]byte{}) {
		return Request{}, ErrInvalid
	}
	reserved := reservation.state
	if reserved.JournalCount() == 0 || reservation.entry.Index()+1 != reserved.JournalCount() {
		return Request{}, ErrInvalid
	}
	store := reserved.StoreID()
	snapshot, transaction := reservation.entry.SnapshotID(), reservation.entry.TransactionID()
	raw := reserved.Bytes()
	binary.BigEndian.PutUint64(raw[24:32], reserved.Sequence()+1)
	copy(raw[32:48], snapshot[:])
	copy(raw[48:80], candidateHash[:])
	copy(raw[80:96], transaction[:])
	next, err := appstoreanchorstate.Parse(raw[:], store)
	if err != nil {
		return Request{}, ErrInvalid
	}
	key := sum("SSAPP-COMMIT-v1", store[:], transaction[:], candidateHash[:])
	return mutation(commitKind, next, reserved.Hash(), key, "SSAPP-COMMIT-REQUEST-ID-v1")
}
