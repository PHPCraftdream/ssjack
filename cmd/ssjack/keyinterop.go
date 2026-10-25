package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"

	"storagehost/internal/keyfile"
)

func readImportedPrivate(path string) ([]byte, error) {
	data, err := readBoundedFile(path, 1024*1024)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	encrypted, err := keyfile.RequiresPassphrase(data)
	if err != nil {
		return nil, err
	}
	var password []byte
	if encrypted {
		password, err = readSecret("Imported key passphrase: ")
		if err != nil {
			return nil, err
		}
	} else {
		fmt.Fprintln(os.Stderr, "Source key is unencrypted. The vault will encrypt its copy; the source file will remain unchanged.")
	}
	defer clear(password)
	return keyfile.ImportSSH(data, password)
}

func exportVaultKey(ctx context.Context, path string, plaintext, vaultSecret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := requireNewPath(path); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "OpenSSH export uses standard protection, not the ssjack Argon2id/AES-layer profile. Use a different passphrase: reusing the vault secret gives attackers a cheaper way to guess that secret.")
	if err := ctx.Err(); err != nil {
		return err
	}
	password, err := confirmedSecretFor("OpenSSH passphrase")
	if err != nil {
		return err
	}
	defer clear(password)
	if err := validateExportSecret(password, vaultSecret); err != nil {
		return err
	}
	if err := publishKeyExport(ctx, path, plaintext, password, keyfile.ExportSSH); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Saved encrypted OpenSSH private key. Vault credentials were not changed.")
	return nil
}

func validateExportSecret(password, vaultSecret []byte) error {
	if len(password) == 0 || len(vaultSecret) == 0 {
		return errors.New("export requires vault authorization and a nonempty export passphrase")
	}
	if subtle.ConstantTimeCompare(password, vaultSecret) == 1 {
		return errors.New("OpenSSH export passphrase must differ from the vault secret")
	}
	return nil
}

func publishKeyExport(ctx context.Context, path string, plaintext, password []byte, encode func([]byte, []byte) ([]byte, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := encode(plaintext, password)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeNewFile(path, encoded, 0600)
}
