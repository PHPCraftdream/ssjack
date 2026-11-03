package appstorecrypto

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

// OwnerWriteProposal correlates a durable owner intent without exposing values.
// Previous state and IDs are concurrency metadata, never authority by themselves.
type OwnerWriteProposal struct {
	Previous      appstoreanchorstate.State
	TransactionID [16]byte
	SnapshotID    [16]byte
	References    []appstoreref.Ref
}

type OwnerWritePrepare func(context.Context, OwnerWriteProposal) error

func ownerWriteProposal(previous appstoreanchorstate.State, entry appstorejournal.Entry, objects []writerObject) (OwnerWriteProposal, error) {
	proposal := OwnerWriteProposal{Previous: previous, TransactionID: entry.TransactionID(), SnapshotID: entry.SnapshotID(), References: make([]appstoreref.Ref, 0, len(objects))}
	for _, object := range objects {
		reference, err := appstoreref.New(previous.StoreID(), object.id, object.version, entry.SnapshotID())
		if err != nil {
			return OwnerWriteProposal{}, err
		}
		proposal.References = append(proposal.References, reference)
	}
	return proposal, nil
}

// WriteFromPrepared calls prepare before journal append or reservation dispatch.
// The callback must persist intent, honor context and not reenter this store.
func (w *SnapshotWriter) WriteFromPrepared(ctx context.Context, expected appstoreanchorstate.State, objects []SnapshotObject, prepare OwnerWritePrepare) (SnapshotCommit, error) {
	if prepare == nil {
		return SnapshotCommit{}, ErrSnapshot
	}
	return w.write(ctx, objects, false, &expected, prepare)
}
