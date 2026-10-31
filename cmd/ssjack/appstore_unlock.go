package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/launch"
)

func rejectAppstoreBrokerEnv() error {
	for _, n := range []string{broker.EnvFile, broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, "SSJACK_APP_ENDPOINT", "SSJACK_APP_TOKEN", "SSJACK_APP_CERTIFICATE_SHA256"} {
		if os.Getenv(n) != "" {
			return errors.New("appstore trust operations cannot run inside a broker session")
		}
	}
	return nil
}

func runAppstoreInspect(ctx context.Context, dir string) (int, error) {
	if err := rejectAppstoreBrokerEnv(); err != nil {
		return 1, err
	}
	if os.Geteuid() == 0 {
		return 1, errors.New("trusted appstore inspection requires a non-root terminal")
	}
	if !appstoreentry.Supported() {
		return 1, appstoreentry.ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return 1, err
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
	if err != nil || !installation.DirectoryMatches(dev, ino) || store.VerifyUnchanged(digest) != nil {
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
	readCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	reply, err := transport.Read(readCtx)
	if err != nil {
		return 1, errors.New("application-store read failed")
	}
	state, ok := reply.State()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || reply.Operation() != appstoreanchorreply.Read || !ok || !state.Valid() || state.StoreID() != installation.Header().StoreID() {
		return 1, errAppstore
	}
	_ = writer
	fmt.Fprintf(os.Stdout, "store_id=%x\ninstallation_sha256=%s\ndirectory_dev=%d\ndirectory_ino=%d\n", installation.Header().StoreID(), hex.EncodeToString(digest[:]), dev, ino)
	if state.Sequence() != 0 {
		fmt.Fprintf(os.Stdout, "encoded_hash=%x\nsequence=%d\n", state.CommittedFileHash(), state.Sequence())
	} else {
		fmt.Fprintln(os.Stdout, "encoded_hash=none\nsequence=0")
	}
	return 0, nil
}

func runAppstoreUnlock(ctx context.Context, command []string) (int, error) {
	if err := rejectAppstoreBrokerEnv(); err != nil {
		return 1, err
	}
	if os.Geteuid() == 0 {
		return 1, errors.New("trusted appstore unlock requires a non-root terminal")
	}
	if !appstoreentry.Supported() {
		return 1, appstoreentry.ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	refBytes, err := readVisibleInput("Exact canonical delivery reference: ", false)
	if err != nil {
		return 1, err
	}
	defer clear(refBytes)
	ref := string(refBytes)
	if err = declarativeauthority.ValidateReference(ref); err != nil {
		return 1, errors.New("reference must be the exact canonical placeholder")
	}
	snapshot, err := declarativeauthority.LoadDelivery(ref, os.Geteuid(), time.Now())
	if err != nil {
		return 1, errors.New("no active delivery grant")
	}
	grants := snapshot.Grants()
	if len(grants) != 1 {
		return 1, errors.New("no unique active delivery grant")
	}
	grant := grants[0]
	store, err := appstoreentry.Open(grant.StorePath)
	if err != nil {
		return 1, errAppstore
	}
	encoded, digest, err := store.Load()
	if err != nil {
		store.Close()
		return 1, errAppstore
	}
	if hex.EncodeToString(digest[:]) != grant.InstallationSHA256 {
		clear(encoded)
		store.Close()
		return 1, errAppstore
	}
	master, err := appstoreReadInput("Application-store master secret: ", false)
	if err != nil {
		clear(master)
		clear(encoded)
		store.Close()
		return 1, errAppstore
	}
	installation, err := appstorecrypto.UnlockInstallation(ctx, encoded, master)
	clear(master)
	clear(encoded)
	if err != nil {
		store.Close()
		return 1, errAppstore
	}
	dev, ino, err := store.Identity()
	if err != nil || dev != grant.DirectoryDev || ino != grant.DirectoryIno || !installation.DirectoryMatches(dev, ino) || store.VerifyUnchanged(digest) != nil {
		installation.Close()
		store.Close()
		return 1, errAppstore
	}
	if store.Close() != nil {
		installation.Close()
		return 1, errAppstore
	}
	parsed, err := appstoreplaceholder.Parse(refBytes)
	if err != nil {
		installation.Close()
		return 1, errAppstore
	}
	session, err := declarativeslice.NewDelivery(ctx, installation, parsed)
	if err != nil {
		installation.Close()
		return 1, err
	}
	defer installation.Close()
	defer session.Close()
	exe, err := os.Executable()
	if err != nil {
		return 1, err
	}
	root, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Restricted synthetic confidential delivery; receipts do not establish adoption.")
	return launch.Run(ctx, launch.Options{Root: root, Mode: broker.ModeDeclarative, Executable: exe, Command: command, BootstrapTTL: 2 * time.Minute, Synthetic: session, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
}
