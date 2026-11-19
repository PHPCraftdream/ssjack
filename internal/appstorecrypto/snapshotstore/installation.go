package snapshotstore

import (
	"context"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

type Installation struct {
	master      *masterkey.Master
	binding     masterkey.Binding
	encodedHash [32]byte
}

func (i *Installation) Header() appstoreheader.Header {
	if i == nil {
		return appstoreheader.Header{}
	}
	return i.binding.Header
}
func (i *Installation) Close() error {
	if i == nil {
		return nil
	}
	clear(i.binding.PrivateDER)
	i.binding.PrivateDER = nil
	if i.master != nil {
		return i.master.Close()
	}
	return nil
}
func (i *Installation) DirectoryMatches(dev, ino uint64) bool {
	return i != nil && dev != 0 && ino != 0 && i.binding.DirectoryDev == dev && i.binding.DirectoryIno == ino
}
func (i *Installation) Writer(directory *appstorefile.Directory) (*SnapshotWriter, *appstoreanchortls.Writer, error) {
	if i == nil || i.master == nil || i.master.Closed() || directory == nil {
		return nil, nil, masterkey.ErrInstallation
	}
	dev, ino, err := directory.Identity()
	if err != nil || i.binding.Header.StoreID() != directory.StoreID() || !i.DirectoryMatches(dev, ino) {
		return nil, nil, masterkey.ErrInstallation
	}
	transport, err := i.binding.Transport()
	if err != nil {
		return nil, nil, err
	}
	writer, err := NewSnapshotWriter(directory, transport, i.master)
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}
	return writer, transport, nil
}
func (i *Installation) CheckSnapshot(ctx context.Context, r io.Reader, expected masterkey.ExpectedSnapshot) (masterkey.SnapshotCheck, error) {
	if i == nil || i.master == nil {
		return masterkey.SnapshotCheck{}, masterkey.ErrInstallation
	}
	return i.master.CheckSnapshot(ctx, r, expected)
}

func UnlockInstallation(ctx context.Context, encoded, p []byte) (*Installation, error) {
	m, binding, encodedHash, err := masterkey.OpenInstallation(ctx, encoded, p)
	if err != nil {
		return nil, err
	}
	return &Installation{master: m, binding: binding, encodedHash: encodedHash}, nil
}

// UnlockInstallationWith is a test seam: UnlockInstallation with a caller-supplied derivation.
func UnlockInstallationWith(ctx context.Context, encoded, p []byte, derive masterkey.DeriveFunc) (*Installation, error) {
	m, binding, encodedHash, err := masterkey.OpenInstallationWith(ctx, encoded, p, derive)
	if err != nil {
		return nil, err
	}
	return &Installation{master: m, binding: binding, encodedHash: encodedHash}, nil
}

// MasterOf returns the unlocked master of an installation for sibling packages.
func MasterOf(i *Installation) *masterkey.Master {
	if i == nil {
		return nil
	}
	return i.master
}

// EncodedHashOf returns the SHA-256 of the encoded installation.
func EncodedHashOf(i *Installation) [32]byte { return i.encodedHash }

// AnchorOf opens a new anchor writer from the installation binding.
func AnchorOf(i *Installation) (*appstoreanchortls.Writer, error) { return i.binding.Transport() }
