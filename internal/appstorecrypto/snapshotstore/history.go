package snapshotstore

import (
	"context"
	"encoding/hex"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func (s *snapshotWriterState) recoverPredecessor(ctx context.Context, tx *appstorefile.Transaction, proposed appstoreanchorstate.State, candidate masterkey.SnapshotCheck) (appstoreanchorstate.State, error) {
	if ctx == nil || tx == nil || s == nil || s.directory == nil || s.master == nil || !proposed.Valid() || proposed.StoreID() != s.directory.StoreID() || !candidate.Valid() {
		return appstoreanchorstate.State{}, masterkey.ErrSnapshot
	}
	store := proposed.StoreID()
	candidateEntries := candidate.Catalog().Entries()
	previous, err := appstoreanchorstate.Genesis(store)
	if err != nil {
		return appstoreanchorstate.State{}, masterkey.ErrSnapshot
	}
	for sequence := uint64(1); sequence < proposed.Sequence(); sequence++ {
		if err := ctx.Err(); err != nil {
			return appstoreanchorstate.State{}, err
		}
		req, err := writerIntentAt(tx, store, sequence)
		if err != nil {
			return appstoreanchorstate.State{}, err
		}
		next, ok := req.ProposedState()
		if !ok || next.Sequence() != sequence || next.JournalCount() <= previous.JournalCount() || next.JournalCount() > proposed.JournalCount() {
			return appstoreanchorstate.State{}, masterkey.ErrSnapshot
		}
		j, err := tx.Journal()
		if err != nil {
			return appstoreanchorstate.State{}, masterkey.ErrSnapshot
		}
		_, err = appstorejournal.InspectPrefix(next, j)
		if err == nil && next.JournalCount() > 0 {
			_, err = j.Seek(int64(next.JournalCount()-1)*appstorejournal.Size, io.SeekStart)
		}
		var rawEntry [appstorejournal.Size]byte
		if err == nil {
			_, err = io.ReadFull(j, rawEntry[:])
		}
		closeErr := j.Close()
		if err != nil || closeErr != nil {
			return appstoreanchorstate.State{}, masterkey.ErrSnapshot
		}
		entry, err := appstorejournal.ParseEntry(rawEntry[:], next.JournalCount()-1)
		if err != nil || entry.SnapshotID() != next.CommittedSnapshotID() || entry.TransactionID() != next.CommittedTransactionID() {
			return appstoreanchorstate.State{}, masterkey.ErrSnapshot
		}
		prevRaw := previous.Bytes()
		nextRaw := next.Bytes()
		copy(prevRaw[96:136], nextRaw[96:136])
		expected, err := appstoreanchorstate.Parse(prevRaw[:], store)
		if err != nil {
			return appstoreanchorstate.State{}, masterkey.ErrSnapshot
		}
		expectedHash, ok := req.ExpectedStateHash()
		if !ok || expectedHash != expected.Hash() {
			return appstoreanchorstate.State{}, masterkey.ErrSnapshot
		}
		quarantined, quarantineErr := writerQuarantined(tx, next.CommittedSnapshotID())
		if quarantineErr != nil || quarantined {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		f, err := tx.OpenSnapshot(next.CommittedSnapshotID())
		if err != nil {
			return appstoreanchorstate.State{}, masterkey.ErrSnapshot
		}
		check, checkErr := masterkey.CheckSnapshotHeld(s.master, ctx, f, masterkey.ExpectedSnapshot{StoreID: store, SnapshotID: next.CommittedSnapshotID(), EncodedHash: next.CommittedFileHash()})
		closeErr = f.Close()
		if checkErr != nil || closeErr != nil || !check.Valid() || check.Header().ParentID() != previous.CommittedSnapshotID() || !s.master.Matches(check.Header()) {
			return appstoreanchorstate.State{}, masterkey.ErrRecord
		}
		checkEntries := check.Catalog().Entries()
		for _, old := range candidateEntries {
			for _, ent := range checkEntries {
				if ent.ObjectID() == old.ObjectID() && ent.VersionID() == old.VersionID() {
					return appstoreanchorstate.State{}, masterkey.ErrRecord
				}
			}
		}
		previous = next
	}
	if proposed.Sequence() != previous.Sequence()+1 || proposed.JournalCount() <= previous.JournalCount() || candidate.Header().ParentID() != previous.CommittedSnapshotID() {
		return appstoreanchorstate.State{}, masterkey.ErrSnapshot
	}
	if previous.Sequence() > 0 {
		f, err := tx.OpenRecovery(previous.CommittedSnapshotID(), proposed.CommittedTransactionID())
		if err != nil {
			return appstoreanchorstate.State{}, masterkey.ErrSnapshot
		}
		check, checkErr := masterkey.CheckSnapshotHeld(s.master, ctx, f, masterkey.ExpectedSnapshot{StoreID: store, SnapshotID: previous.CommittedSnapshotID(), EncodedHash: previous.CommittedFileHash()})
		closeErr := f.Close()
		if checkErr != nil || closeErr != nil || !check.Valid() {
			return appstoreanchorstate.State{}, masterkey.ErrSnapshot
		}
	}
	raw := previous.Bytes()
	proposedRaw := proposed.Bytes()
	copy(raw[96:136], proposedRaw[96:136])
	reconstructed, err := appstoreanchorstate.Parse(raw[:], store)
	if err != nil {
		return appstoreanchorstate.State{}, masterkey.ErrSnapshot
	}
	return reconstructed, nil
}
func (s *snapshotWriterState) checkWriterHistory(ctx context.Context, tx *appstorefile.Transaction, current appstoreanchorstate.State, proposed []writerObject) error {
	if ctx == nil || tx == nil || s == nil || s.directory == nil || s.master == nil || !current.Valid() || current.StoreID() != s.directory.StoreID() {
		return masterkey.ErrSnapshot
	}
	store := current.StoreID()
	if err := ctx.Err(); err != nil {
		return err
	}
	if current.Sequence() == 0 {
		if current.CommittedSnapshotID() != ([16]byte{}) || current.CommittedTransactionID() != ([16]byte{}) || current.CommittedFileHash() != ([32]byte{}) {
			return masterkey.ErrSnapshot
		}
		for _, kind := range []string{"intents", "snapshots", "candidates", "recovery"} {
			if err := tx.Entries(kind, func(string) error { return ErrWriterPending }); err != nil {
				return err
			}
		}
		return nil
	}
	var previous, selected appstoreanchorstate.State
	previous, err := appstoreanchorstate.Genesis(store)
	if err != nil {
		return masterkey.ErrSnapshot
	}
	historyIDs := make([][16]byte, 0, int(current.Sequence()))
	for sequence := uint64(1); sequence <= current.Sequence(); sequence++ {
		var found bool
		var chosen appstoreanchorrequest.Request
		if err := tx.Entries("intents", func(name string) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if len(name) != 36 || name[32:] != ".bin" {
				return masterkey.ErrSnapshot
			}
			b, e := hex.DecodeString(name[:32])
			if e != nil || len(b) != 16 || hex.EncodeToString(b) != name[:32] {
				return masterkey.ErrSnapshot
			}
			var txn [16]byte
			copy(txn[:], b)
			raw, e := tx.LoadIntent(txn)
			if e != nil {
				return masterkey.ErrSnapshot
			}
			intent, e := appstoreanchorrequest.ParseIntent(raw[:], store)
			if e != nil {
				return masterkey.ErrSnapshot
			}
			req, ok := intent.Request()
			if !ok {
				return masterkey.ErrSnapshot
			}
			n, ok := req.ProposedState()
			if !ok {
				return masterkey.ErrSnapshot
			}
			if n.Sequence() > current.Sequence() {
				return ErrWriterPending
			}
			if n.Sequence() == sequence {
				if found {
					return masterkey.ErrSnapshot
				}
				found, chosen = true, req
			}
			return nil
		}); err != nil {
			return err
		}
		if !found {
			return masterkey.ErrSnapshot
		}
		next, _ := chosen.ProposedState()
		if next.Sequence() != sequence || next.Sequence() != previous.Sequence()+1 || next.JournalCount() <= previous.JournalCount() || next.JournalCount() > current.JournalCount() {
			return masterkey.ErrSnapshot
		}
		j, e := tx.Journal()
		if e != nil {
			return masterkey.ErrSnapshot
		}
		prefix, e := appstorejournal.InspectPrefix(next, j)
		if e != nil || prefix.Count() != next.JournalCount() || next.JournalCount() == 0 {
			j.Close()
			return masterkey.ErrSnapshot
		}
		if _, e = j.Seek(int64(next.JournalCount()-1)*appstorejournal.Size, io.SeekStart); e != nil {
			j.Close()
			return masterkey.ErrSnapshot
		}
		var rawEntry [appstorejournal.Size]byte
		_, e = io.ReadFull(j, rawEntry[:])
		j.Close()
		if e != nil {
			return masterkey.ErrSnapshot
		}
		entry, e := appstorejournal.ParseEntry(rawEntry[:], next.JournalCount()-1)
		if e != nil || entry.SnapshotID() != next.CommittedSnapshotID() || entry.TransactionID() != next.CommittedTransactionID() {
			return masterkey.ErrSnapshot
		}
		prevRaw := previous.Bytes()
		nextRaw := next.Bytes()
		copy(prevRaw[96:136], nextRaw[96:136])
		expected, ok := chosen.ExpectedStateHash()
		if !ok {
			return masterkey.ErrSnapshot
		}
		expectedReserved, e := appstoreanchorstate.Parse(prevRaw[:], store)
		if e != nil || expected != expectedReserved.Hash() {
			return masterkey.ErrSnapshot
		}
		quarantined, quarantineErr := writerQuarantined(tx, next.CommittedSnapshotID())
		if quarantineErr != nil || quarantined {
			return ErrWriterPending
		}
		f, e := tx.OpenSnapshot(next.CommittedSnapshotID())
		if e != nil {
			return masterkey.ErrSnapshot
		}
		check, e := masterkey.CheckSnapshotHeld(s.master, ctx, f, masterkey.ExpectedSnapshot{StoreID: store, SnapshotID: next.CommittedSnapshotID(), EncodedHash: next.CommittedFileHash()})
		closeErr := f.Close()
		if e != nil || closeErr != nil || !check.Valid() || check.Header().SnapshotID() != next.CommittedSnapshotID() || check.Header().ParentID() != previous.CommittedSnapshotID() || !s.master.Matches(check.Header()) {
			return masterkey.ErrSnapshot
		}
		for _, id := range historyIDs {
			if id == next.CommittedSnapshotID() {
				return masterkey.ErrSnapshot
			}
		}
		checkEntries := check.Catalog().Entries()
		for _, old := range proposed {
			for _, ent := range checkEntries {
				if ent.ObjectID() == old.id && ent.VersionID() == old.version {
					return masterkey.ErrSnapshot
				}
			}
		}
		previous, selected = next, next
		historyIDs = append(historyIDs, next.CommittedSnapshotID())
	}
	if selected.Sequence() != current.Sequence() || selected.CommittedSnapshotID() != current.CommittedSnapshotID() || selected.CommittedTransactionID() != current.CommittedTransactionID() || selected.CommittedFileHash() != current.CommittedFileHash() {
		return ErrWriterPending
	}
	var snapshotCount uint64
	if err := tx.Entries("snapshots", func(name string) error {
		snapshotCount++
		if len(name) != 36 || name[32:] != ".bin" {
			return masterkey.ErrSnapshot
		}
		b, e := hex.DecodeString(name[:32])
		if e != nil || len(b) != 16 || hex.EncodeToString(b) != name[:32] {
			return masterkey.ErrSnapshot
		}
		var id [16]byte
		copy(id[:], b)
		found := false
		for _, known := range historyIDs {
			if known == id {
				found = true
				break
			}
		}
		if !found {
			return masterkey.ErrSnapshot
		}
		return nil
	}); err != nil {
		return err
	}
	if snapshotCount != uint64(len(historyIDs)) {
		return masterkey.ErrSnapshot
	}
	if err := tx.Entries("candidates", func(string) error { return ErrWriterPending }); err != nil {
		return err
	}
	if err := tx.Entries("recovery", func(name string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(name) != 69 || name[32] != '-' || name[65:] != ".bin" {
			return ErrWriterPending
		}
		decodeID := func(text string) ([16]byte, bool) {
			var id [16]byte
			b, e := hex.DecodeString(text)
			if e != nil || len(b) != len(id) || hex.EncodeToString(b) != text {
				return id, false
			}
			copy(id[:], b)
			return id, id != ([16]byte{})
		}
		snapshotID, ok := decodeID(name[:32])
		if !ok {
			return ErrWriterPending
		}
		txnID, ok := decodeID(name[33:65])
		if !ok {
			return ErrWriterPending
		}
		var matched bool
		var expectedHash [32]byte
		var oldState appstoreanchorstate.State
		if err := tx.Entries("intents", func(intentName string) error {
			if len(intentName) != 36 || intentName[32:] != ".bin" {
				return ErrWriterPending
			}
			id, valid := decodeID(intentName[:32])
			if !valid {
				return ErrWriterPending
			}
			raw, e := tx.LoadIntent(id)
			if e != nil {
				return ErrWriterPending
			}
			intent, e := appstoreanchorrequest.ParseIntent(raw[:], store)
			if e != nil {
				return ErrWriterPending
			}
			req, exists := intent.Request()
			if !exists {
				return ErrWriterPending
			}
			state, exists := req.ProposedState()
			if !exists || state.CommittedSnapshotID() != snapshotID {
				return nil
			}
			if matched || state.Sequence() > current.Sequence() {
				return ErrWriterPending
			}
			matched = true
			expectedHash = state.CommittedFileHash()
			oldState = state
			return nil
		}); err != nil {
			return err
		}
		if !matched {
			return ErrWriterPending
		}
		known := false
		for _, id := range historyIDs {
			if id == snapshotID {
				known = true
				break
			}
		}
		if !known {
			return ErrWriterPending
		}
		journal, err := tx.Journal()
		if err != nil {
			return ErrWriterPending
		}
		var journalMatch bool
		for index := oldState.JournalCount(); index < current.JournalCount(); index++ {
			var raw [appstorejournal.Size]byte
			if _, err = journal.ReadAt(raw[:], int64(index)*appstorejournal.Size); err != nil {
				break
			}
			entry, parseErr := appstorejournal.ParseEntry(raw[:], index)
			if parseErr != nil {
				err = parseErr
				break
			}
			if entry.TransactionID() == txnID {
				if journalMatch {
					err = masterkey.ErrSnapshot
					break
				}
				journalMatch = true
			}
		}
		closeErr := journal.Close()
		if err != nil || closeErr != nil || !journalMatch {
			return ErrWriterPending
		}
		f, err := tx.OpenNamed("recovery", name)
		if err != nil {
			return ErrWriterPending
		}
		check, checkErr := masterkey.CheckSnapshotHeld(s.master, ctx, f, masterkey.ExpectedSnapshot{StoreID: store, SnapshotID: snapshotID, EncodedHash: expectedHash})
		closeErr = f.Close()
		if checkErr != nil || closeErr != nil || !check.Valid() || check.Header().SnapshotID() != snapshotID || !s.master.Matches(check.Header()) {
			return ErrWriterPending
		}
		parentKnown := check.Header().ParentID() == ([16]byte{}) && snapshotID == historyIDs[0]
		for _, id := range historyIDs {
			if id == check.Header().ParentID() {
				parentKnown = true
				break
			}
		}
		if !parentKnown {
			return ErrWriterPending
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
