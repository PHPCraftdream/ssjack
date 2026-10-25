package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"

	"storagehost/internal/vault"
)

func confirmValue(prompt, expected string) error {
	value, err := readSecret(prompt)
	if err != nil {
		return err
	}
	defer clear(value)
	if subtle.ConstantTimeCompare(value, []byte(expected)) != 1 {
		return errors.New("confirmation did not match; operation cancelled")
	}
	return nil
}

func runVaultMaintenance(ctx context.Context, path, profile string, args []string) (int, error) {
	if len(args) == 2 && args[0] == "migrate" {
		return runLegacyMigration(ctx, path, profile, args[1])
	}
	if len(args) == 1 && args[0] == "init" {
		return runInitProfile(ctx, path, profile)
	}
	if len(args) == 1 && args[0] == "passwd" {
		return runVaultCommand(ctx, path, args)
	}
	if len(args) != 2 || (args[0] != "backup" && args[0] != "check" && args[0] != "restore") {
		return 1, errors.New("usage: ssjack vault init|passwd|backup FILE|check FILE|restore FILE; use ssjack help vault")
	}
	if args[0] == "backup" {
		if err := requireNewPath(args[1]); err != nil {
			return 1, err
		}
		password, err := readSecret("Vault secret: ")
		if err != nil {
			return 1, err
		}
		defer clear(password)
		if err := vault.Backup(ctx, path, args[1], password); err != nil {
			return 1, err
		}
		fmt.Fprintln(os.Stderr, "Saved a verified encrypted database backup. Keep its secret and public parameters recoverable.")
		return 0, nil
	}
	password, err := readSecret("Backup secret: ")
	if err != nil {
		return 1, err
	}
	defer clear(password)
	if args[0] == "check" {
		if err := vault.Verify(args[1], password); err != nil {
			return 1, err
		}
		if err := ctx.Err(); err != nil {
			return 1, err
		}
		fmt.Fprintln(os.Stdout, "OK: encrypted backup authentication, parameters, and records verified; no files changed.")
		return 0, nil
	}
	var current []byte
	if _, err := os.Lstat(path); err == nil {
		current, err = readSecret("Current vault secret: ")
		if err != nil {
			return 1, err
		}
	} else if !os.IsNotExist(err) {
		return 1, err
	}
	defer clear(current)
	plan, err := vault.PrepareRestore(path, args[1], password, current)
	if err != nil {
		return 1, err
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Backup and current database verified. The restored database will use the BACKUP secret. An existing database receives an encrypted recovery copy before replacement.")
	if err := confirmValue("Type RESTORE to replace the database: ", "RESTORE"); err != nil {
		return 1, err
	}
	previous, err := plan.Commit(ctx)
	if previous != "" {
		fmt.Fprintf(os.Stderr, "Previous encrypted database retained: %q\n", previous)
	}
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Encrypted backup restored. Source backup and recovery copy were not deleted.")
	return 0, nil
}
