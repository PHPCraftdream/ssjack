package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
)

func runAppstorePut(ctx context.Context, dir string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if !appstoreentry.Supported() {
		return 1, appstoreentry.ErrUnsupported
	}
	store, err := appstoreentry.Open(dir)
	if err != nil {
		return 1, errAppstore
	}
	defer store.Close()
	encoded, digest, err := store.Load()
	if err != nil {
		return 1, errAppstore
	}
	defer clear(encoded)
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	master, err := appstoreReadInput("Application-store master secret: ", false)
	if err != nil {
		clear(master)
		return 1, errAppstore
	}
	defer clear(master)
	installation, err := appstorecrypto.UnlockInstallation(ctx, encoded, master)
	if err != nil {
		return 1, errAppstore
	}
	defer installation.Close()
	dev, ino, err := store.Identity()
	if err != nil || !installation.DirectoryMatches(dev, ino) {
		return 1, errAppstore
	}
	if store.VerifyUnchanged(digest) != nil {
		return 1, errAppstore
	}
	root, err := store.Root()
	if err != nil {
		return 1, errAppstore
	}
	defer root.Close()
	directory, err := appstorefile.Open(root, installation.Header().StoreID())
	if err != nil {
		return 1, errAppstore
	}
	defer directory.Close()
	writer, transport, err := installation.Writer(directory)
	if err != nil {
		return 1, errAppstore
	}
	defer transport.Close()
	opctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := opctx.Err(); err != nil {
		return 1, err
	}
	reply, err := transport.Read(opctx)
	if err != nil {
		return 1, errors.New("application-store read failed")
	}
	if reply.Operation() != appstoreanchorreply.Read || reply.Outcome() != appstoreanchorreply.ReadState {
		return 1, errors.New("application-store authority read was not successful")
	}
	state, present := reply.State()
	if !present || !state.Valid() || state.StoreID() != installation.Header().StoreID() {
		return 1, errAppstore
	}
	if state.Sequence() != 0 || state.CommittedSnapshotID() != ([16]byte{}) {
		return 1, errors.New("application-store already has committed data; put is first-entry only")
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if store.VerifyUnchanged(digest) != nil {
		return 1, errors.New("installation authority changed; no mutation sent")
	}
	secret, err := appstoreReadInput("Secret (max 16 KiB): ", false)
	if err != nil {
		clear(secret)
		return 1, errAppstore
	}
	if err = ctx.Err(); err != nil {
		clear(secret)
		return 1, err
	}
	var objectID [16]byte
	if _, err = rand.Read(objectID[:]); err != nil {
		clear(secret)
		return 1, errAppstore
	}
	object, closeObject, err := appstorecrypto.NewSecretObject(objectID, "text/plain", secret)
	clear(secret)
	if err != nil {
		return 1, errAppstore
	}
	defer closeObject()
	if err = ctx.Err(); err != nil {
		return 1, err
	}
	if store.VerifyUnchanged(digest) != nil {
		return 1, errors.New("installation authority changed; no mutation sent")
	}
	callctx, cancelCall := context.WithTimeout(ctx, 60*time.Second)
	defer cancelCall()
	commit, err := writer.WriteFirst(callctx, []appstorecrypto.SnapshotObject{object})
	if err != nil {
		return 1, writerFailure(err)
	}
	if len(commit.Refs) != 1 {
		return 1, errors.New("application-store mutation result invalid; inspect/reconcile before any new mutation")
	}
	placeholder, err := appstoreplaceholder.Encode(commit.Refs[0])
	if err != nil {
		return 1, errors.New("application-store committed; output encoding failed")
	}
	if _, err = io.WriteString(os.Stdout, string(placeholder)+"\n"); err != nil {
		clear(placeholder)
		return 1, errors.New("application-store committed; placeholder output failed")
	}
	clear(placeholder)
	if _, err := fmt.Fprintf(os.Stdout, "sequence=%d revision=%d\n", commit.State.Sequence(), commit.State.JournalCount()); err != nil {
		return 1, errors.New("application-store committed; revision output failed")
	}
	return 0, nil
}

func writerFailure(err error) error {
	switch {
	case errors.Is(err, appstorecrypto.ErrWriterPending):
		return errors.New("application-store outcome pending or uncertain; inspect/reconcile before any new mutation")
	case errors.Is(err, appstorecrypto.ErrWriterBurned):
		return errors.New("application-store reservation burned; inspect/reconcile before any new mutation")
	case errors.Is(err, appstorecrypto.ErrWriterRejected):
		return errors.New("application-store mutation rejected; inspect/reconcile before any new mutation")
	case errors.Is(err, appstorecrypto.ErrWriterPointerLag):
		return errors.New("application-store pointer lag; inspect/reconcile before any new mutation")
	default:
		return errors.New("application-store mutation outcome uncertain; inspect/reconcile before any new mutation")
	}
}
