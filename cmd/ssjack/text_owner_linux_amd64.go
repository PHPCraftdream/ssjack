//go:build linux && amd64

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerresource"
	"github.com/PHPCraftdream/ssjack/internal/ownerservice"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// runOwnedTextAdapter consumes the already unlocked, linked version-2 vault.
func runOwnedTextAdapter(ctx context.Context, path string, loaded *vault.Vault, request ownerresource.TextRequest, command []string) (code int, result error) {
	if len(command) == 0 {
		return 1, errors.New("text adapter requires an explicit harness")
	}
	owner, credentials, err := startTextOwner(ctx, path, loaded)
	if credentials != nil {
		defer finishAgentCredentials(credentials, &code, &result)
	}
	if err != nil {
		return 1, err
	}
	consumer, err := owner.ServeText(ctx, request)
	if err != nil {
		return 1, errors.New("linked text-adapter grant validation failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if consumer.Close(cleanup) != nil {
			code, result = 1, errOwnerShutdown
		}
	}()
	child := exec.CommandContext(ctx, command[0], command[1:]...)
	child.Env = apptransport.Environment(os.Environ(), consumer.Bootstrap())
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err = child.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

// startTextOwner transfers one authenticated v2 unlock, including partial startup.
func startTextOwner(ctx context.Context, path string, loaded *vault.Vault) (*ownerdb.Manager, *agentCredentials, error) {
	owner, err := ownerdb.Adopt(ctx, path, loaded)
	if err != nil {
		return nil, nil, err
	}
	credentials := &agentCredentials{owner: owner}
	service, err := ownerservice.Start(ctx, owner)
	if err != nil {
		return owner, credentials, err
	}
	credentials.service = service
	return owner, credentials, nil
}

func unlockTextInstallation(ctx context.Context, grant declarativeauthority.TextAdapterGrant) (*appstorecrypto.Installation, error) {
	store, err := appstoreentry.Open(grant.StorePath)
	if err != nil {
		return nil, errAppstore
	}
	encoded, hash, err := store.Load()
	if err != nil {
		store.Close()
		return nil, errAppstore
	}
	if hex.EncodeToString(hash[:]) != grant.InstallationSHA256 {
		clear(encoded)
		store.Close()
		return nil, errAppstore
	}
	master, err := appstoreReadInput("Application-store master secret: ", false)
	if err != nil {
		clear(master)
		clear(encoded)
		store.Close()
		return nil, errAppstore
	}
	installation, err := appstorecrypto.UnlockInstallation(ctx, encoded, master)
	clear(master)
	clear(encoded)
	if err != nil {
		store.Close()
		return nil, errAppstore
	}
	dev, ino, err := store.Identity()
	unchanged := store.VerifyUnchanged(hash)
	_ = store.Close()
	if err != nil || unchanged != nil || dev != grant.DirectoryDev || ino != grant.DirectoryIno || !installation.DirectoryMatches(dev, ino) {
		installation.Close()
		return nil, errAppstore
	}
	return installation, nil
}
