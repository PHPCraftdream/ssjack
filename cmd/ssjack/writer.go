package main

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func openManagedVaultForWrite(ctx context.Context, path string) (*vault.Vault, []byte, error) {
	loaded, secret, err := openManagedVault(ctx, path)
	if err != nil {
		return nil, nil, err
	}
	if err := loaded.ClaimWriter(path); err != nil {
		loaded.Close()
		clear(secret)
		return nil, nil, err
	}
	return loaded, secret, nil
}

func writesVault(action string) bool {
	switch action {
	case "passwd", "add", "edit", "remove", "import":
		return true
	}
	return false
}
