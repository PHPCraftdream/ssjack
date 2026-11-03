package appstorecrypto

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func ownerPointer(state appstoreanchorstate.State) [64]byte {
	var pointer [64]byte
	snapshot, encoded, transaction := state.CommittedSnapshotID(), state.CommittedFileHash(), state.CommittedTransactionID()
	copy(pointer[:16], snapshot[:])
	copy(pointer[16:48], encoded[:])
	copy(pointer[48:], transaction[:])
	return pointer
}

func (o *OwnerEditor) verifyState(ctx context.Context, tx *appstorefile.Transaction, state appstoreanchorstate.State) error {
	fresh, err := writerRead(ctx, o.transport, state.StoreID())
	if err != nil {
		return err
	}
	if fresh.Hash() != state.Hash() {
		return ErrOwnerChanged
	}
	if state.Sequence() != 0 {
		pointer, err := tx.ReadPointer()
		if err != nil || pointer != ownerPointer(state) {
			return ErrWriterPointerLag
		}
	}
	return ctx.Err()
}

func (o *OwnerEditor) load(ctx context.Context) error {
	s := o.writer.state
	release, err := appstorebudget.TryAcquire(s.directory.StoreID())
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.directory.Lock()
	if err != nil {
		return err
	}
	defer tx.Close()
	state, err := writerRead(ctx, o.transport, s.directory.StoreID())
	if err != nil {
		return err
	}
	if err := s.checkWriterHistory(ctx, tx, state, nil); err != nil {
		return err
	}
	if state.Sequence() == 0 {
		if err := o.verifyState(ctx, tx, state); err != nil {
			return err
		}
		o.base = state
		return nil
	}
	if err := o.verifyState(ctx, tx, state); err != nil {
		return err
	}
	spool, err := s.master.pinSnapshot(ctx, tx, ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: state.CommittedSnapshotID(), EncodedHash: state.CommittedFileHash()})
	if err != nil {
		return err
	}
	defer spool.close()
	entries := spool.state.checked.Catalog().Entries()
	if len(entries) > MaxOwnerObjects {
		return ErrRecord
	}
	seen := make(map[[16]byte]bool)
	for _, entry := range entries {
		if entry.Length() > maxRAMSecretSize || seen[entry.ObjectID()] {
			return ErrRecord
		}
		seen[entry.ObjectID()] = true
	}
	for _, entry := range entries {
		value := make([]byte, 0, int(entry.Length()))
		result, err := s.master.streamPinnedObjectToChecked(ctx, spool, entry, writerBuffer{data: &value}, ctx.Err)
		if err != nil || result.Bytes != entry.Length() {
			clear(value)
			return ErrRecord
		}
		reference, err := appstoreref.New(state.StoreID(), entry.ObjectID(), entry.VersionID(), state.CommittedSnapshotID())
		if err != nil {
			clear(value)
			return ErrRecord
		}
		o.objects[entry.ObjectID()] = ownerObject{value: value, media: entry.MediaType(), reference: reference}
	}
	if err := spool.recheck(ctx); err != nil {
		return err
	}
	if err := o.verifyState(ctx, tx, state); err != nil {
		return err
	}
	o.base = state
	return nil
}
