package main

import (
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

func exportVaultKey(path string, plaintext []byte) error {
	if err := requireNewPath(path); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "OpenSSH export uses standard protection, not the ssjack Argon2id/AES-layer profile. Use a different passphrase: reusing the vault secret gives attackers a cheaper way to guess that secret.")
	password, err := confirmedSecretFor("OpenSSH passphrase")
	if err != nil {
		return err
	}
	defer clear(password)
	encoded, err := keyfile.ExportSSH(plaintext, password)
	if err != nil {
		return err
	}
	if err := writeNewFile(path, encoded, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Saved encrypted OpenSSH private key. Vault credentials were not changed.")
	return nil
}
