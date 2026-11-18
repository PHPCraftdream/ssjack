package delivery

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoresink"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
)

// Private until an authenticated enrollment path can own consumer configuration.
func deliverCurrent(m *masterkey.Master, ctx context.Context, directory *appstorefile.Directory, anchor interface {
	Read(context.Context) (appstoreanchorreply.Reply, error)
}, reference appstoreref.Ref, consumer *appstoresink.Consumer, checks ...func() error) (appstoresink.Result, error) {
	return deliverSelected(m, ctx, directory, anchor, reference, consumer, nil, checks...)
}

func deliverCurrentText(m *masterkey.Master, ctx context.Context, directory *appstorefile.Directory, anchor interface {
	Read(context.Context) (appstoreanchorreply.Reply, error)
}, reference appstoreref.Ref, consumer *appstoresink.Consumer, selection *textSelection, checks ...func() error) (appstoresink.Result, error) {
	if selection == nil || len(selection.input) > 32<<10 {
		return appstoresink.Result{}, ErrDelivery
	}
	return deliverSelected(m, ctx, directory, anchor, reference, consumer, selection, checks...)
}

func deliverSelected(m *masterkey.Master, ctx context.Context, directory *appstorefile.Directory, anchor interface {
	Read(context.Context) (appstoreanchorreply.Reply, error)
}, reference appstoreref.Ref, consumer *appstoresink.Consumer, selection *textSelection, checks ...func() error) (appstoresink.Result, error) {
	if ctx == nil || directory == nil || anchor == nil || consumer == nil {
		return appstoresink.Result{}, masterkey.ErrSnapshot
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, fn := range checks {
			if fn != nil {
				if err := fn(); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	binding := consumer.Binding()
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	if directory.StoreID() != reference.StoreID() {
		return appstoresink.Result{}, masterkey.ErrSnapshot
	}
	if err := consumer.Check(reference, binding.EncodedHash); err != nil {
		return appstoresink.Result{}, err
	}
	release, err := appstorebudget.TryAcquire(reference.StoreID())
	if err != nil {
		return appstoresink.Result{}, masterkey.ErrBusy
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer tx.Close()
	reply, err := anchor.Read(ctx)
	if err != nil {
		return appstoresink.Result{}, err
	}
	state, present := reply.State()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || state.StoreID() != reference.StoreID() || state.CommittedSnapshotID() != reference.SnapshotID() || state.CommittedFileHash() != binding.EncodedHash {
		return appstoresink.Result{}, masterkey.ErrSnapshot
	}
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	pointer, err := tx.ReadPointer()
	if err != nil {
		return appstoresink.Result{}, err
	}
	var wanted [64]byte
	snapshot, encoded, transaction := state.CommittedSnapshotID(), state.CommittedFileHash(), state.CommittedTransactionID()
	copy(wanted[:16], snapshot[:])
	copy(wanted[16:48], encoded[:])
	copy(wanted[48:], transaction[:])
	if pointer != wanted {
		return appstoresink.Result{}, snapshotstore.ErrWriterPointerLag
	}
	spool, err := PinSnapshot(m, ctx, tx, masterkey.ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: snapshot, EncodedHash: encoded})
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer spool.Close()
	entry, err := appstoreref.FindMetadata(reference, spool.state.checked.Catalog())
	if err != nil {
		return appstoresink.Result{}, err
	}
	if err = spool.Recheck(ctx); err != nil {
		return appstoresink.Result{}, err
	}
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	if err = consumer.Check(reference, encoded); err != nil {
		return appstoresink.Result{}, err
	}
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	// Preserve the signed anchor snapshot and writer pointer through full verification.
	fresh, err := anchor.Read(ctx)
	if err != nil {
		return appstoresink.Result{}, err
	}
	freshState, freshPresent := fresh.State()
	if !fresh.SignatureValid() || fresh.Outcome() != appstoreanchorreply.ReadState || !freshPresent || !freshState.Valid() || freshState.Hash() != state.Hash() {
		return appstoresink.Result{}, masterkey.ErrSnapshot
	}
	freshPointer, err := tx.ReadPointer()
	if err != nil || freshPointer != wanted {
		return appstoresink.Result{}, snapshotstore.ErrWriterPointerLag
	}
	if selection != nil {
		return deliverTextSelection(m, ctx, spool, entry, reference, consumer, encoded, selection, check)
	}
	session, err := consumer.Begin(ctx, reference, encoded, entry.Length())
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer session.Close()
	result, err := streamPinnedObject(m, ctx, spool, entry, session, check)
	if err != nil {
		return result, err
	}
	if err = spool.Recheck(ctx); err != nil {
		return result, err
	}
	if err := check(); err != nil {
		return result, err
	}
	if err := consumer.Check(reference, encoded); err != nil {
		return result, err
	}
	if err := check(); err != nil {
		return result, err
	}
	return session.Finish()
}

type textSelection struct {
	input   []byte
	reverse bool
}

func transformTextSelection(reference appstoreref.Ref, secret, selection []byte, reverse bool) ([]byte, error) {
	return appstoretext.Replace(selection, []appstoretext.Mapping{{Reference: reference, Value: secret}}, reverse)
}

func deliverTextSelection(m *masterkey.Master, ctx context.Context, spool *PinnedSnapshot, entry appstorecatalog.Entry, reference appstoreref.Ref, consumer *appstoresink.Consumer, encoded [32]byte, selection *textSelection, check func() error) (appstoresink.Result, error) {
	if selection == nil || entry.Length() > appstoretext.MaxText {
		return appstoresink.Result{}, ErrDelivery
	}
	secret := make([]byte, 0, entry.Length())
	collected, err := StreamPinned(m, ctx, spool, entry, Buffer{Data: &secret}, check)
	if err != nil || collected.Bytes != entry.Length() {
		clear(secret)
		return appstoresink.Result{}, masterkey.ErrSnapshot
	}
	defer clear(secret)
	transformed, err := transformTextSelection(reference, secret, selection.input, selection.reverse)
	if err != nil {
		return appstoresink.Result{}, ErrDelivery
	}
	defer clear(transformed)
	if err = spool.Recheck(ctx); err != nil {
		return appstoresink.Result{}, err
	}
	if err = check(); err != nil {
		return appstoresink.Result{}, err
	}
	if err = consumer.Check(reference, encoded); err != nil {
		return appstoresink.Result{}, err
	}
	session, err := consumer.Begin(ctx, reference, encoded, uint64(len(transformed)))
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer session.Close()
	result := appstoresink.Result{}
	for len(transformed) > 0 {
		if err = check(); err != nil {
			return result, err
		}
		n := len(transformed)
		if n > 16384 {
			n = 16384
		}
		result.MayHaveDelivered = true
		written, writeErr := session.Write(transformed[:n])
		result.Bytes += uint64(written)
		if writeErr != nil || written != n {
			return result, appstoresink.ErrUnavailable
		}
		transformed = transformed[n:]
	}
	if err = spool.Recheck(ctx); err != nil {
		return result, err
	}
	if err = consumer.Check(reference, encoded); err != nil {
		return result, err
	}
	if err = check(); err != nil {
		return result, err
	}
	return session.Finish()
}
