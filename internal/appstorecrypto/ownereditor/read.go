package ownereditor

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/delivery"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func (o *OwnerEditor) verifyState(ctx context.Context, tx *appstorefile.Transaction, state appstoreanchorstate.State) error {
	fresh, err := snapshotstore.ReadAnchor(ctx, o.transport, state.StoreID())
	if err != nil {
		return err
	}
	if fresh.Hash() != state.Hash() {
		return snapshotstore.ErrOwnerChanged
	}
	if state.Sequence() != 0 {
		pointer, err := tx.ReadPointer()
		if err != nil || pointer != snapshotstore.Pointer(state) {
			return snapshotstore.ErrWriterPointerLag
		}
	}
	return ctx.Err()
}

func (o *OwnerEditor) load(ctx context.Context) error {
	directory, master := snapshotstore.WriterDirectory(o.writer), snapshotstore.WriterMaster(o.writer)
	release, err := appstorebudget.TryAcquire(directory.StoreID())
	if err != nil {
		return err
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		return err
	}
	defer tx.Close()
	state, err := snapshotstore.ReadAnchor(ctx, o.transport, directory.StoreID())
	if err != nil {
		return err
	}
	if err := snapshotstore.CheckHistory(ctx, o.writer, tx, state); err != nil {
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
	spool, err := delivery.PinSnapshot(master, ctx, tx, masterkey.ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: state.CommittedSnapshotID(), EncodedHash: state.CommittedFileHash()})
	if err != nil {
		return err
	}
	defer spool.Close()
	entries := spool.Catalog().Entries()
	if len(entries) > snapshotstore.MaxOwnerObjects {
		return masterkey.ErrRecord
	}
	seen := make(map[[16]byte]bool)
	for _, entry := range entries {
		if entry.Length() > snapshotstore.MaxRAMSecretSize || seen[entry.ObjectID()] {
			return masterkey.ErrRecord
		}
		seen[entry.ObjectID()] = true
	}
	for _, entry := range entries {
		value := make([]byte, 0, int(entry.Length()))
		result, err := delivery.StreamPinned(master, ctx, spool, entry, delivery.Buffer{Data: &value}, ctx.Err)
		if err != nil || result.Bytes != entry.Length() {
			clear(value)
			return masterkey.ErrRecord
		}
		reference, err := appstoreref.New(state.StoreID(), entry.ObjectID(), entry.VersionID(), state.CommittedSnapshotID())
		if err != nil {
			clear(value)
			return masterkey.ErrRecord
		}
		o.objects[entry.ObjectID()] = ownerObject{value: value, media: entry.MediaType(), reference: reference}
	}
	if err := spool.Recheck(ctx); err != nil {
		return err
	}
	if err := o.verifyState(ctx, tx, state); err != nil {
		return err
	}
	o.base = state
	return nil
}
