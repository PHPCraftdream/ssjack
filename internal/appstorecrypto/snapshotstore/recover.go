package snapshotstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorresult"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func (w *SnapshotWriter) Recover(ctx context.Context) (SnapshotCommit, error) {
	return w.recover(ctx, nil)
}

func (w *SnapshotWriter) recover(ctx context.Context, expectedOwner *OwnerRecoveryExpectation) (SnapshotCommit, error) {
	if w == nil || w.state == nil || ctx == nil {
		return SnapshotCommit{}, masterkey.ErrSnapshot
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	s := w.state
	if !s.mu.TryLock() {
		return SnapshotCommit{}, masterkey.ErrBusy
	}
	defer s.mu.Unlock()
	release, err := appstorebudget.TryAcquire(s.directory.StoreID())
	if err != nil {
		return SnapshotCommit{}, masterkey.ErrBusy
	}
	defer release()
	tx, err := s.directory.Lock()
	if err != nil {
		if errors.Is(err, appstorefile.ErrBusy) {
			return SnapshotCommit{}, masterkey.ErrBusy
		}
		return SnapshotCommit{}, err
	}
	defer tx.Close()
	anchor, err := writerRead(ctx, s.transport, s.directory.StoreID())
	if err != nil {
		return SnapshotCommit{}, err
	}
	if expectedOwner != nil {
		if err := s.guardOwnerRecovery(ctx, tx, anchor, *expectedOwner); err != nil {
			return SnapshotCommit{}, err
		}
	}
	anchor, err = writerReconcileReservations(ctx, tx, s.transport, anchor)
	if err != nil {
		return SnapshotCommit{}, err
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	jf, err := tx.Journal()
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	prefix, err := appstorejournal.InspectPrefix(anchor, jf)
	if err != nil {
		_ = jf.Close()
		return SnapshotCommit{}, ErrWriterPending
	}
	if _, err = jf.Seek(0, io.SeekEnd); err != nil {
		_ = jf.Close()
		return SnapshotCommit{}, ErrWriterPending
	}
	eof, err := jf.Seek(0, io.SeekCurrent)
	_ = jf.Close()
	if err != nil || eof != int64(prefix.Count())*appstorejournal.Size || prefix.Count() == 0 {
		return SnapshotCommit{}, ErrWriterPending
	}
	jf, err = tx.Journal()
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	_, err = jf.Seek(int64(prefix.Count()-1)*appstorejournal.Size, io.SeekStart)
	var rawEntry [appstorejournal.Size]byte
	if err == nil {
		_, err = io.ReadFull(jf, rawEntry[:])
	}
	_ = jf.Close()
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	entry, err := appstorejournal.ParseEntry(rawEntry[:], prefix.Count()-1)
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	txn, snapshot := entry.TransactionID(), entry.SnapshotID()
	rawIntent, err := tx.LoadIntent(txn)
	if errors.Is(err, appstorefile.ErrMissing) {
		return SnapshotCommit{State: anchor}, ErrWriterBurned
	}
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	intent, err := appstoreanchorrequest.ParseIntent(rawIntent[:], anchor.StoreID())
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	req, ok := intent.Request()
	if !ok {
		return SnapshotCommit{}, ErrWriterPending
	}
	proposed, ok := req.ProposedState()
	if !ok || proposed.CommittedSnapshotID() != snapshot || proposed.CommittedTransactionID() != txn || proposed.JournalCount() != prefix.Count() || proposed.JournalHead() != prefix.Head() {
		return SnapshotCommit{}, ErrWriterPending
	}
	expected, ok := req.ExpectedStateHash()
	if !ok {
		return SnapshotCommit{}, ErrWriterPending
	}
	reserved := anchor.Hash() == expected
	committed := anchor.Bytes() == proposed.Bytes()
	if !reserved && !committed {
		return SnapshotCommit{}, ErrWriterPending
	}
	quarantined, quarantineErr := writerQuarantined(tx, snapshot)
	if quarantineErr != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	if quarantined {
		return SnapshotCommit{State: anchor}, ErrWriterBurned
	}
	var f *os.File
	candidatePresent := true
	f, err = tx.OpenCandidate(snapshot)
	if errors.Is(err, appstorefile.ErrMissing) && committed {
		candidatePresent = false
		f, err = tx.OpenSnapshot(snapshot)
	}
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	check, checkErr := masterkey.CheckSnapshotHeld(s.master, ctx, f, masterkey.ExpectedSnapshot{StoreID: anchor.StoreID(), SnapshotID: snapshot, EncodedHash: proposed.CommittedFileHash()})
	closeErr := f.Close()
	if checkErr != nil || closeErr != nil || !check.Valid() {
		return SnapshotCommit{}, ErrWriterPending
	}
	store := anchor.StoreID()
	reservedState, proofErr := s.recoverPredecessor(ctx, tx, proposed, check)
	if proofErr != nil || expected != reservedState.Hash() {
		return SnapshotCommit{}, ErrWriterPending
	}
	if reserved {
		if err := tx.SyncCandidate(snapshot); err != nil {
			return SnapshotCommit{}, ErrWriterPending
		}
		if anchor.Bytes() != reservedState.Bytes() {
			return SnapshotCommit{}, ErrWriterPending
		}
		if err := ctx.Err(); err != nil {
			return SnapshotCommit{}, err
		}
		loaded, loadErr := tx.LoadIntent(txn)
		if loadErr != nil || loaded != rawIntent {
			return SnapshotCommit{}, ErrWriterPending
		}
		reply, classification, submitErr := s.transport.Submit(ctx, req)
		if writerSubmissionRejected(req, reply, classification, submitErr) {
			return SnapshotCommit{}, ErrWriterRejected
		}
		anchor, err = writerRead(ctx, s.transport, store)
		if err != nil || anchor.Bytes() != proposed.Bytes() {
			return SnapshotCommit{}, ErrWriterPending
		}
	} else if anchor.Bytes() != proposed.Bytes() {
		return SnapshotCommit{}, ErrWriterPending
	}
	out := SnapshotCommit{State: proposed, EncodedHash: proposed.CommittedFileHash()}
	for _, ent := range check.Catalog().Entries() {
		ref, e := appstoreref.New(anchor.StoreID(), ent.ObjectID(), ent.VersionID(), snapshot)
		if e != nil {
			return SnapshotCommit{}, ErrWriterPending
		}
		out.Refs = append(out.Refs, ref)
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	if candidatePresent {
		if err := tx.Publish(snapshot); err != nil {
			return out, ErrWriterPointerLag
		}
	}
	var tuple [64]byte
	copy(tuple[:16], snapshot[:])
	hash := proposed.CommittedFileHash()
	copy(tuple[16:48], hash[:])
	copy(tuple[48:], txn[:])
	if err := tx.Pointer(tuple); err != nil {
		return out, ErrWriterPointerLag
	}
	return out, nil
}

func writerReconcileReservations(ctx context.Context, tx *appstorefile.Transaction, transport *appstoreanchortls.Writer, observed appstoreanchorstate.State) (appstoreanchorstate.State, error) {
	if ctx == nil || tx == nil || transport == nil || !observed.Valid() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	journal, err := tx.Journal()
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	defer journal.Close()
	revision, err := appstorefile.Stat(journal)
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	if revision.Size < 0 || revision.Size > 40*int64(appstoreanchorstate.MaxReservations) || revision.Size%40 != 0 {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	localTotal := uint64(revision.Size / 40)
	if localTotal < observed.JournalCount() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	if _, err = journal.Seek(0, io.SeekStart); err != nil {
		return appstoreanchorstate.State{}, err
	}
	if _, err = appstorejournal.InspectPrefix(observed, journal); err != nil {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	if err = tx.SyncJournal(); err != nil {
		return appstoreanchorstate.State{}, err
	}
	state := observed
	var raw [appstorejournal.Size]byte
	// Reservations before the committed cursor are burned if they have no
	// corresponding intent. Valid intents are left for normal recovery.
	for index := uint64(0); index < state.JournalCount(); index++ {
		if err = ctx.Err(); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = journal.Seek(int64(index*appstorejournal.Size), io.SeekStart); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = io.ReadFull(journal, raw[:]); err != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		entry, parseErr := appstorejournal.ParseEntry(raw[:], index)
		if parseErr != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		if entry.SnapshotID() == state.CommittedSnapshotID() {
			if entry.TransactionID() != state.CommittedTransactionID() {
				return appstoreanchorstate.State{}, ErrWriterPending
			}
			continue
		}
		if _, intentErr := tx.LoadIntent(entry.TransactionID()); errors.Is(intentErr, appstorefile.ErrMissing) {
			if err = tx.Quarantine(entry.SnapshotID()); err != nil && !errors.Is(err, appstorefile.ErrMissing) {
				return appstoreanchorstate.State{}, err
			}
		} else if intentErr != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
	}
	for index := observed.JournalCount(); index < localTotal; index++ {
		if err = ctx.Err(); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = journal.Seek(int64(index*appstorejournal.Size), io.SeekStart); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = io.ReadFull(journal, raw[:]); err != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		entry, parseErr := appstorejournal.ParseEntry(raw[:], index)
		if parseErr != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		if _, err = journal.Seek(0, io.SeekStart); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = appstorejournal.CheckFreshPair(state, journal, entry); err != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		req, planErr := appstoreanchorrequest.PlanReservation(state, entry)
		if planErr != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		if err = tx.Quarantine(entry.SnapshotID()); err != nil && !errors.Is(err, appstorefile.ErrMissing) {
			return appstoreanchorstate.State{}, err
		}
		fresh, readErr := writerRead(ctx, transport, state.StoreID())
		if readErr != nil {
			return appstoreanchorstate.State{}, readErr
		}
		proposed, _ := req.ProposedState()
		if fresh.Bytes() == proposed.Bytes() {
			state = fresh
		} else if fresh.Bytes() == state.Bytes() {
			state, err = writerMutate(ctx, transport, req, state)
			if err != nil {
				return appstoreanchorstate.State{}, err
			}
		} else {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
	}
	fresh, readErr := writerRead(ctx, transport, state.StoreID())
	if readErr != nil {
		return appstoreanchorstate.State{}, readErr
	}
	if fresh.Bytes() != state.Bytes() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	return fresh, nil
}

func writerRead(ctx context.Context, w *appstoreanchortls.Writer, store [16]byte) (appstoreanchorstate.State, error) {
	reply, err := w.Read(ctx)
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	if !reply.SignatureValid() || reply.Operation() != appstoreanchorreply.Read || reply.Outcome() != appstoreanchorreply.ReadState {
		return appstoreanchorstate.State{}, masterkey.ErrSnapshot
	}
	state, ok := reply.State()
	if !ok || state.StoreID() != store {
		return appstoreanchorstate.State{}, masterkey.ErrSnapshot
	}
	return state, nil
}
func writerSubmissionRejected(request appstoreanchorrequest.Request, reply appstoreanchorreply.Reply, classification appstoreanchorresult.MutationResult, err error) bool {
	if classification == appstoreanchorresult.ReportedRejected {
		return true
	}
	if err != nil || !reply.SignatureValid() || byte(reply.Operation()) != request.Operation() || reply.RequestID() != request.RequestID() || reply.StoreID() != request.StoreID() || reply.Outcome() != appstoreanchorreply.Rejected {
		return false
	}
	return true
}

func writerMutate(ctx context.Context, w *appstoreanchortls.Writer, req appstoreanchorrequest.Request, expected appstoreanchorstate.State) (appstoreanchorstate.State, error) {
	reply, classification, submitErr := w.Submit(ctx, req)
	if writerSubmissionRejected(req, reply, classification, submitErr) {
		return appstoreanchorstate.State{}, ErrWriterRejected
	}
	got, err := writerRead(ctx, w, req.StoreID())
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	proposed, _ := req.ProposedState()
	if got.Bytes() == proposed.Bytes() {
		return got, nil
	}
	if got.Bytes() != expected.Bytes() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	reply, classification, submitErr = w.Submit(ctx, req)
	if writerSubmissionRejected(req, reply, classification, submitErr) {
		return appstoreanchorstate.State{}, ErrWriterRejected
	}
	got, err = writerRead(ctx, w, req.StoreID())
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	if got.Bytes() != proposed.Bytes() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	return got, nil
}
func newWriterEntry(s appstoreanchorstate.State, store [16]byte) (appstorejournal.Entry, error) {
	var snap, txn [16]byte
	for snap == ([16]byte{}) || txn == ([16]byte{}) || snap == txn {
		if _, e := rand.Read(snap[:]); e != nil {
			return appstorejournal.Entry{}, e
		}
		if _, e := rand.Read(txn[:]); e != nil {
			return appstorejournal.Entry{}, e
		}
	}
	_ = store
	return appstorejournal.NewEntry(s.JournalCount(), snap, txn)
}

func writerIntentAt(tx *appstorefile.Transaction, store [16]byte, sequence uint64) (appstoreanchorrequest.Request, error) {
	var chosen appstoreanchorrequest.Request
	var found bool
	if tx == nil || store == ([16]byte{}) || sequence == 0 {
		return chosen, ErrWriterPending
	}
	err := tx.Entries("intents", func(name string) error {
		if len(name) != 36 || name[32:] != ".bin" {
			return ErrWriterPending
		}
		decoded, err := hex.DecodeString(name[:32])
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != name[:32] {
			return ErrWriterPending
		}
		var txn [16]byte
		copy(txn[:], decoded)
		raw, err := tx.LoadIntent(txn)
		if err != nil {
			return ErrWriterPending
		}
		intent, err := appstoreanchorrequest.ParseIntent(raw[:], store)
		if err != nil {
			return ErrWriterPending
		}
		req, ok := intent.Request()
		if !ok {
			return ErrWriterPending
		}
		state, ok := req.ProposedState()
		if !ok {
			return ErrWriterPending
		}
		if state.Sequence() == sequence {
			if found {
				return ErrWriterPending
			}
			chosen, found = req, true
		}
		return nil
	})
	if err != nil {
		return appstoreanchorrequest.Request{}, err
	}
	if !found {
		return appstoreanchorrequest.Request{}, ErrWriterPending
	}
	return chosen, nil
}

func validMedia(s string) bool {
	if len(s) < 1 || len(s) > 15 {
		return false
	}
	slash := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' {
			if slash || i == 0 || i == len(s)-1 {
				return false
			}
			slash = true
		} else if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '.' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

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
		return SnapshotCommit{}, masterkey.ErrSnapshot
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
	check, checkErr := masterkey.CheckSnapshotHeld(s.master, ctx, file, masterkey.ExpectedSnapshot{StoreID: anchor.StoreID(), SnapshotID: expected.SnapshotID, EncodedHash: proposed.CommittedFileHash()})
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

// ValidMedia reports whether s is an accepted object media type.
func ValidMedia(s string) bool { return validMedia(s) }

// NewEntry builds the next journal entry for a state; a test seam for sibling packages.
func NewEntry(s appstoreanchorstate.State, store [16]byte) (appstorejournal.Entry, error) {
	return newWriterEntry(s, store)
}
