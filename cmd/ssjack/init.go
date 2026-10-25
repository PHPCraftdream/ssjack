package main

import (
	"context"
	"fmt"
	"os"

	"storagehost/internal/vault"
)

func runInitProfile(ctx context.Context, path, name string) (int, error) {
	return runInitProfileWithKey(ctx, path, name, false)
}

func runInitProfileWithKey(ctx context.Context, path, name string, generate bool) (int, error) {
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if err := requireNewPath(path); err != nil {
		return 1, err
	}
	secret, err := confirmedSecretFor("database secret")
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	v := vault.New()
	var public, private []byte
	if generate {
		if err := ctx.Err(); err != nil {
			return 1, err
		}
		v, err = vault.NewUnlocked(secret)
		if err != nil {
			return 1, err
		}
		defer v.Close()
		if err := ctx.Err(); err != nil {
			return 1, err
		}
		public, private, err = v.GenerateIdentity()
		if err != nil {
			return 1, err
		}
		defer clear(private)
	} else {
		defer v.Close()
	}
	fmt.Fprintln(os.Stderr, "Configure the first encrypted profile:", name)
	target, err := editVaultTargetWithPrivate(vault.Target{}, false, private)
	if err != nil {
		return 1, err
	}
	v.Targets[name] = target
	save := func() error {
		if generate {
			return vault.CreateUnlocked(ctx, path, v)
		}
		return vault.CreateWithRecords(ctx, path, v, secret)
	}
	if err := saveProfileWithInstructions(ctx, save, os.Stdout, public); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Created encrypted database and complete profile:", name)
	return 0, nil
}
