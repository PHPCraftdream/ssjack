package ownerdb

import (
	"context"
	"encoding/hex"
	"errors"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type resources struct {
	store        *appstoreentry.Store
	root         *os.File
	directory    *appstorefile.Directory
	installation *appstorecrypto.Installation
	editor       *appstorecrypto.OwnerEditor
	digest       [32]byte
}

func openResources(ctx context.Context, link *vault.OwnerStore) (_ *resources, err error) {
	if link == nil || !appstoreentry.Supported() {
		return nil, errors.New("linked application-store editing is unavailable")
	}
	r := &resources{}
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	r.store, err = appstoreentry.Open(link.Directory)
	if err != nil {
		return nil, err
	}
	encoded, digest, err := r.store.Load()
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	r.digest = digest
	r.installation, err = appstorecrypto.UnlockInstallation(ctx, encoded, link.Master)
	if err != nil {
		return nil, errors.New("linked application-store unlock failed")
	}
	storeID := r.installation.Header().StoreID()
	if hex.EncodeToString(storeID[:]) != link.StoreID {
		return nil, errors.New("linked application-store identity changed")
	}
	dev, ino, err := r.store.Identity()
	if err != nil || !r.installation.DirectoryMatches(dev, ino) {
		return nil, errors.New("linked installation directory changed")
	}
	r.root, err = r.store.Root()
	if err != nil {
		return nil, err
	}
	r.directory, err = appstorefile.Open(r.root, storeID)
	if err != nil {
		return nil, err
	}
	if err = r.check(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *resources) check() error {
	if r == nil || r.store == nil || r.directory == nil || r.installation == nil {
		return errors.New("linked owner resources are unavailable")
	}
	if err := r.store.VerifyUnchanged(r.digest); err != nil {
		return errors.New("linked installation changed during the owner session")
	}
	dev, ino, err := r.directory.Identity()
	if err != nil || !r.installation.DirectoryMatches(dev, ino) {
		return errors.New("linked application-store directory changed")
	}
	return nil
}

func (r *resources) openEditor(ctx context.Context) error {
	if err := r.check(); err != nil {
		return err
	}
	if r.editor != nil {
		return nil
	}
	var err error
	r.editor, err = appstorecrypto.NewOwnerEditor(ctx, r.installation, r.directory)
	return err
}

func (r *resources) close() {
	if r == nil {
		return
	}
	if r.editor != nil {
		r.editor.Close()
	}
	if r.directory != nil {
		r.directory.Close()
	}
	if r.root != nil {
		r.root.Close()
	}
	if r.installation != nil {
		r.installation.Close()
	}
	if r.store != nil {
		r.store.Close()
	}
}
