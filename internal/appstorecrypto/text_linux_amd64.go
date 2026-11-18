//go:build linux && amd64

package appstorecrypto

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/textadapter"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
)

type (
	TextAdapter       = textadapter.TextAdapter
	TextAdapterRunner = textadapter.TextAdapterRunner
	TextStreamAdapter = textadapter.TextStreamAdapter
)

func NewTextAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextAdapter, error) {
	return textadapter.NewTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner)
}

func NewReverseTextAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextAdapter, error) {
	return textadapter.NewReverseTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner)
}

func NewBorrowedTextAdapter(ctx context.Context, installation *Installation, store *appstoreentry.Store, directory *appstorefile.Directory, grantID, profile, credentialDigest string, runner TextAdapterRunner, mode string) (*TextAdapter, error) {
	return textadapter.NewBorrowedTextAdapter(ctx, installation, store, directory, grantID, profile, credentialDigest, runner, mode)
}

func NewTextStreamAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextStreamAdapter, error) {
	return textadapter.NewTextStreamAdapter(ctx, installation, grantID, profile, credentialDigest, runner)
}

func NewReverseTextStreamAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextStreamAdapter, error) {
	return textadapter.NewReverseTextStreamAdapter(ctx, installation, grantID, profile, credentialDigest, runner)
}

func NewBorrowedTextStreamAdapter(ctx context.Context, installation *Installation, store *appstoreentry.Store, directory *appstorefile.Directory, grantID, profile, credentialDigest string, runner TextAdapterRunner, mode string) (*TextStreamAdapter, error) {
	return textadapter.NewBorrowedTextStreamAdapter(ctx, installation, store, directory, grantID, profile, credentialDigest, runner, mode)
}
