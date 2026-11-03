package main

import (
	"context"
	"fmt"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func runDirectoryMigration(ctx context.Context, source, destination string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if err := requireNewPath(destination); err != nil {
		return 1, err
	}
	password, err := readSecret("Vault secret: ")
	if err != nil {
		return 1, err
	}
	defer clear(password)
	plan, err := vault.PrepareDirectoryMigration(ctx, source, password)
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Verified the legacy database and encrypted named-directory replacement. Each profile becomes a server with one main account. The source remains unchanged; old binaries must use that original file.")
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if err := confirmValue("Type MIGRATE DIRECTORY to create the new encrypted database: ", "MIGRATE DIRECTORY"); err != nil {
		return 1, err
	}
	if err := plan.Commit(ctx, destination); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Created the verified encrypted directory database. Select it explicitly with --vault; keep the unchanged original for rollback. No server was contacted.")
	return 0, nil
}
