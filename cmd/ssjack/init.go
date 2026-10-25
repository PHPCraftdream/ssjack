package main

import (
	"context"
	"fmt"
	"os"

	"storagehost/internal/vault"
)

func runInitProfile(ctx context.Context, path, name string) (int, error) {
	if err := requireNewPath(path); err != nil {
		return 1, err
	}
	secret, err := confirmedSecretFor("database secret")
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	fmt.Fprintln(os.Stderr, "Configure the first encrypted profile:", name)
	target, err := editVaultTarget(vault.Target{}, false)
	if err != nil {
		return 1, err
	}
	v := vault.New()
	defer v.Close()
	v.Targets[name] = target
	if err := vault.CreateWithRecords(ctx, path, v, secret); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Created encrypted database and complete profile:", name)
	return 0, nil
}
