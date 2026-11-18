package appstorecrypto

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
)

type (
	Installation             = snapshotstore.Installation
	SnapshotWriter           = snapshotstore.SnapshotWriter
	SnapshotObject           = snapshotstore.SnapshotObject
	SnapshotCommit           = snapshotstore.SnapshotCommit
	OwnerWriteProposal       = snapshotstore.OwnerWriteProposal
	OwnerWritePrepare        = snapshotstore.OwnerWritePrepare
	OwnerRecoveryExpectation = snapshotstore.OwnerRecoveryExpectation
)

const MaxOwnerObjects = snapshotstore.MaxOwnerObjects

var (
	ErrWriterPointerLag  = snapshotstore.ErrWriterPointerLag
	ErrWriterPending     = snapshotstore.ErrWriterPending
	ErrWriterBurned      = snapshotstore.ErrWriterBurned
	ErrWriterRejected    = snapshotstore.ErrWriterRejected
	ErrOwnerChanged      = snapshotstore.ErrOwnerChanged
	ErrOwnerUndispatched = snapshotstore.ErrOwnerUndispatched
)

func UnlockInstallation(ctx context.Context, encoded, p []byte) (*Installation, error) {
	return snapshotstore.UnlockInstallation(ctx, encoded, p)
}

func NewSnapshotWriter(directory *appstorefile.Directory, transport *appstoreanchortls.Writer, master *Master) (*SnapshotWriter, error) {
	return snapshotstore.NewSnapshotWriter(directory, transport, master)
}

// NewSecretObject copies a secret of at most 16 KiB into writer-owned RAM.
// Its returned close function clears that owned copy; host swap is outside this guarantee.
func NewSecretObject(objectID [16]byte, media string, secret []byte) (SnapshotObject, func(), error) {
	return snapshotstore.NewSecretObject(objectID, media, secret)
}
