// Package appstorecrypto is the public face of the app-store crypto runtime. It owns
// dedicated app-store key material, not authority; implementations live in subpackages.
package appstorecrypto

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

type (
	Master           = masterkey.Master
	Binding          = masterkey.Binding
	ExpectedSnapshot = masterkey.ExpectedSnapshot
	SnapshotCheck    = masterkey.SnapshotCheck
)

var (
	ErrInvalid        = masterkey.ErrInvalid
	ErrDerivation     = masterkey.ErrDerivation
	ErrInstallation   = masterkey.ErrInstallation
	ErrRecord         = masterkey.ErrRecord
	ErrClosed         = masterkey.ErrClosed
	ErrBusy           = masterkey.ErrBusy
	ErrAuthentication = masterkey.ErrAuthentication
	ErrSnapshot       = masterkey.ErrSnapshot
	ErrSnapshotRead   = masterkey.ErrSnapshotRead
)

// Derive does not verify a passphrase, authenticate a snapshot or permit encryption.
func Derive(ctx context.Context, header appstoreheader.Header, passphrase []byte) (*Master, error) {
	return masterkey.Derive(ctx, header, passphrase)
}

func NewInstallation(ctx context.Context, h appstoreheader.Header, p []byte, b Binding) ([]byte, error) {
	return masterkey.NewInstallation(ctx, h, p, b)
}
