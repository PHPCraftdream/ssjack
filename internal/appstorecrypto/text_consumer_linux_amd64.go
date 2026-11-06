//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"encoding/hex"
	"os"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func NewTextAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextAdapter, error) {
	return newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "hydrate-v1")
}

func NewReverseTextAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextAdapter, error) {
	return newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "reverse-copy-v1")
}

func newTextAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner, expectedMode string) (*TextAdapter, error) {
	return newTextConsumer(ctx, installation, nil, nil, grantID, profile, credentialDigest, runner, expectedMode)
}

// NewBorrowedTextAdapter borrows keeper-owned handles; Close never releases them.
func NewBorrowedTextAdapter(ctx context.Context, installation *Installation, store *appstoreentry.Store, directory *appstorefile.Directory, grantID, profile, credentialDigest string, runner TextAdapterRunner, mode string) (*TextAdapter, error) {
	if store == nil || directory == nil {
		return nil, ErrDelivery
	}
	return newTextConsumer(ctx, installation, store, directory, grantID, profile, credentialDigest, runner, mode)
}

func newTextConsumer(ctx context.Context, installation *Installation, store *appstoreentry.Store, directory *appstorefile.Directory, grantID, profile, credentialDigest string, runner TextAdapterRunner, expectedMode string) (*TextAdapter, error) {
	if !validTextAdapterMode(expectedMode) || ctx == nil || installation == nil || installation.master == nil || installation.master.Closed() || runner == nil || !digestPattern.MatchString(credentialDigest) || os.Geteuid() <= 0 {
		return nil, ErrDelivery
	}
	g, err := loadTextAdapterGrant(expectedMode, grantID, os.Geteuid(), time.Now())
	if err != nil || g.Mode != expectedMode || g.Profile != profile || g.CredentialSHA256 != credentialDigest || hex.EncodeToString(installation.encodedHash[:]) != g.InstallationSHA256 || installation.Header().StoreID() == ([16]byte{}) || len(g.References) == 0 {
		return nil, ErrDelivery
	}
	borrowed := store != nil
	if !borrowed {
		store, err = appstoreentry.Open(g.StorePath)
		if err != nil {
			return nil, ErrDelivery
		}
	}
	fail := func() (*TextAdapter, error) {
		if !borrowed {
			_ = store.Close()
		}
		return nil, ErrDelivery
	}
	if !borrowed {
		encoded, actual, loadErr := store.Load()
		clear(encoded)
		if loadErr != nil || actual != installation.encodedHash {
			return fail()
		}
	}
	dev, ino, err := store.Identity()
	if err != nil || store.VerifyUnchanged(installation.encodedHash) != nil || dev != g.DirectoryDev || ino != g.DirectoryIno || !installation.DirectoryMatches(dev, ino) || installation.Header().StoreID() != mustTextStore(g) {
		return fail()
	}
	if !borrowed {
		root, rootErr := store.Root()
		if rootErr != nil {
			return fail()
		}
		directory, err = appstorefile.Open(root, installation.Header().StoreID())
		_ = root.Close()
		if err != nil {
			return fail()
		}
	}
	directoryDev, directoryIno, err := directory.Identity()
	if err != nil || directoryDev != dev || directoryIno != ino || directory.StoreID() != installation.Header().StoreID() {
		if !borrowed {
			_ = directory.Close()
		}
		return fail()
	}
	_, anchor, err := installation.Writer(directory)
	if err != nil {
		if !borrowed {
			_ = directory.Close()
		}
		return fail()
	}
	binding, err := newTextBinding()
	if err != nil {
		_ = anchor.Close()
		if !borrowed {
			_ = directory.Close()
		}
		return fail()
	}
	adapter := &TextAdapter{installation: installation, grant: g, store: store, directory: directory, anchor: anchor, runner: runner, binding: binding, borrowed: borrowed}
	if adapter.check(ctx) != nil {
		_ = adapter.Close()
		return nil, ErrDelivery
	}
	return adapter, nil
}

func mustTextStore(g declarativeauthority.TextAdapterGrant) [16]byte {
	if len(g.References) == 0 {
		return [16]byte{}
	}
	r, err := appstoreplaceholder.Parse([]byte(g.References[0]))
	if err != nil {
		return [16]byte{}
	}
	return r.StoreID()
}

func NewBorrowedTextStreamAdapter(ctx context.Context, installation *Installation, store *appstoreentry.Store, directory *appstorefile.Directory, grantID, profile, credentialDigest string, runner TextAdapterRunner, mode string) (*TextStreamAdapter, error) {
	if mode != "hydrate-stream-v2" && mode != "reverse-copy-stream-v2" {
		return nil, ErrDelivery
	}
	base, err := NewBorrowedTextAdapter(ctx, installation, store, directory, grantID, profile, credentialDigest, runner, mode)
	if err != nil {
		return nil, err
	}
	return &TextStreamAdapter{adapter: base}, nil
}
