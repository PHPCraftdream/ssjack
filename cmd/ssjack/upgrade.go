package main

import (
	"context"
	"fmt"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func runVaultUpgrade(ctx context.Context, path string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	password, err := readSecret("Vault secret: ")
	if err != nil {
		return 1, err
	}
	defer clear(password)
	plan, err := vault.PrepareUpgrade(ctx, path, password)
	if err != nil {
		return 1, err
	}
	if !plan.Needed() {
		if _, err := plan.Commit(ctx); err != nil {
			return 1, err
		}
		fmt.Fprintln(os.Stderr, "Already using opaque format v2; authenticated database left unchanged.")
		return 0, nil
	}
	fmt.Fprintln(os.Stderr, "Verified v1 database and v2 replacement. This hides outer metadata, not algorithms from public source. Old binaries need the preserved v1 copy; other backups remain unchanged.")
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if err := confirmValue("Type UPGRADE to preserve v1 and replace the database: ", "UPGRADE"); err != nil {
		return 1, err
	}
	previous, err := plan.Commit(ctx)
	if previous != "" {
		fmt.Fprintf(os.Stderr, "Original encrypted database retained: %q\n", previous)
	}
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Upgraded to opaque format v2. The vault secret and SSH identities are unchanged.")
	return 0, nil
}
