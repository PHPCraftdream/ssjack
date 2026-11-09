package appstorecrypto

import (
	"context"
	"errors"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

var ErrOwnerUndispatched = errors.New("owner proposal has verified no-dispatch evidence")

type OwnerRecoveryExpectation struct {
	TransactionID [16]byte
	SnapshotID    [16]byte
	PreviousHash  [32]byte
	Versions      map[[16]byte][16]byte
}

// RecoverOwner is explicit reconciliation, never a new secret write or retry.
func (w *SnapshotWriter) RecoverOwner(ctx context.Context, expected OwnerRecoveryExpectation) (SnapshotCommit, error) {
	if expected.TransactionID == ([16]byte{}) || expected.SnapshotID == ([16]byte{}) || expected.PreviousHash == ([32]byte{}) || len(expected.Versions) > MaxOwnerObjects {
		return SnapshotCommit{}, ErrSnapshot
	}
	return w.recover(ctx, &expected)
}

func (s *snapshotWriterState) guardOwnerRecovery(ctx context.Context, tx *appstorefile.Transaction, anchor appstoreanchorstate.State, expected OwnerRecoveryExpectation) error {
	journal, err := tx.Journal()
	if err != nil {
		return err
	}
	defer journal.Close()
	stat, err := appstorefile.Stat(journal)
	if err != nil || stat.Size < 0 || stat.Size%appstorejournal.Size != 0 || stat.Size > int64(appstoreanchorstate.MaxReservations)*appstorejournal.Size {
		return ErrWriterPending
	}
	if _, err := appstorejournal.InspectPrefix(anchor, journal); err != nil {
		return ErrWriterPending
	}
	count := uint64(stat.Size / appstorejournal.Size)
	if count < anchor.JournalCount() {
		return ErrWriterPending
	}
	found := false
	var last appstorejournal.Entry
	for index := uint64(0); index < count; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := journal.Seek(int64(index)*appstorejournal.Size, io.SeekStart); err != nil {
			return err
		}
		var raw [appstorejournal.Size]byte
		if _, err := io.ReadFull(journal, raw[:]); err != nil {
			return err
		}
		last, err = appstorejournal.ParseEntry(raw[:], index)
		if err != nil {
			return ErrWriterPending
		}
		if last.TransactionID() == expected.TransactionID || last.SnapshotID() == expected.SnapshotID {
			if found || last.TransactionID() != expected.TransactionID || last.SnapshotID() != expected.SnapshotID {
				return ErrWriterPending
			}
			found = true
		}
	}
	if !found {
		if count != anchor.JournalCount() || anchor.Hash() != expected.PreviousHash {
			return ErrWriterPending
		}
		if _, err := tx.LoadIntent(expected.TransactionID); !errors.Is(err, appstorefile.ErrMissing) {
			return ErrWriterPending
		}
		return s.ownerNoDispatchArtifacts(tx, expected)
	}
	if last.TransactionID() != expected.TransactionID || last.SnapshotID() != expected.SnapshotID {
		return ErrWriterPending
	}
	rawIntent, err := tx.LoadIntent(expected.TransactionID)
	if errors.Is(err, appstorefile.ErrMissing) {
		if anchor.CommittedTransactionID() == expected.TransactionID || anchor.CommittedSnapshotID() == expected.SnapshotID {
			return ErrWriterPending
		}
		return nil
	}
	if err != nil {
		return ErrWriterPending
	}
	intent, err := appstoreanchorrequest.ParseIntent(rawIntent[:], anchor.StoreID())
	if err != nil {
		return ErrWriterPending
	}
	request, ok := intent.Request()
	if !ok {
		return ErrWriterPending
	}
	proposed, ok := request.ProposedState()
	if !ok || proposed.CommittedTransactionID() != expected.TransactionID || proposed.CommittedSnapshotID() != expected.SnapshotID {
		return ErrWriterPending
	}
	file, err := tx.OpenCandidate(expected.SnapshotID)
	if errors.Is(err, appstorefile.ErrMissing) {
		file, err = tx.OpenSnapshot(expected.SnapshotID)
	}
	if err != nil {
		return ErrWriterPending
	}
	check, checkErr := s.master.checkSnapshot(ctx, file, ExpectedSnapshot{StoreID: anchor.StoreID(), SnapshotID: expected.SnapshotID, EncodedHash: proposed.CommittedFileHash()})
	closeErr := file.Close()
	if checkErr != nil || closeErr != nil || !check.Valid() || len(check.Catalog().Entries()) != len(expected.Versions) {
		return ErrWriterPending
	}
	for _, entry := range check.Catalog().Entries() {
		if expected.Versions[entry.ObjectID()] != entry.VersionID() {
			return ErrWriterPending
		}
	}
	return nil
}

func (s *snapshotWriterState) ownerNoDispatchArtifacts(tx *appstorefile.Transaction, expected OwnerRecoveryExpectation) error {
	candidate, err := tx.OpenCandidate(expected.SnapshotID)
	if err == nil {
		candidate.Close()
		return ErrWriterPending
	}
	if !errors.Is(err, appstorefile.ErrMissing) {
		return ErrWriterPending
	}
	snapshot, err := tx.OpenSnapshot(expected.SnapshotID)
	if err == nil {
		snapshot.Close()
		return ErrWriterPending
	}
	if !errors.Is(err, appstorefile.ErrMissing) {
		return ErrWriterPending
	}
	return ErrOwnerUndispatched
}
