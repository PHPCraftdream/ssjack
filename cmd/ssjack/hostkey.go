package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"

	"storagehost/internal/vault"
)

func openManagedVault(path string) (*vault.Vault, []byte, error) {
	secret, err := readSecret("Vault secret: ")
	if err != nil {
		return nil, nil, err
	}
	v, err := vault.Load(path, secret)
	if err != nil {
		clear(secret)
		return nil, nil, err
	}
	return v, secret, nil
}

func runHostKey(ctx context.Context, path string, args []string) (int, error) {
	if !((len(args) == 2 && args[0] == "show") || (len(args) == 3 && args[0] == "replace")) {
		return 1, errors.New("usage: ssjack hostkey show NAME | replace NAME FILE; use ssjack help hostkey")
	}
	if err := vault.ValidateName(args[1]); err != nil {
		return 1, err
	}
	v, secret, err := openManagedVault(path)
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	defer v.Close()
	target, exists := v.Targets[args[1]]
	if !exists {
		return 1, errors.New("credential record does not exist")
	}
	fmt.Fprintln(os.Stdout, "Trusted SERVER keys for", args[1])
	for _, encoded := range target.HostKeys {
		key, err := vault.ParseHostKey([]byte(encoded))
		if err != nil {
			return 1, err
		}
		fmt.Fprintln(os.Stdout, key.Type(), ssh.FingerprintSHA256(key))
	}
	if args[0] == "show" {
		return 0, nil
	}
	data, err := readBoundedFile(args[2], 16384)
	if err != nil {
		return 1, err
	}
	key, err := vault.ParseHostKey(data)
	clear(data)
	if err != nil {
		return 1, err
	}
	fingerprint := ssh.FingerprintSHA256(key)
	fmt.Fprintln(os.Stderr, "Replacement SERVER key:", key.Type(), fingerprint)
	fmt.Fprintln(os.Stderr, "This command did not obtain trust from the network. Verify this fingerprint through an independent trusted channel; it replaces all existing pins for this record.")
	if err := confirmValue("Type the replacement fingerprint to confirm: ", fingerprint); err != nil {
		return 1, err
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if err := v.ReplaceHostKeys(args[1], []string{string(ssh.MarshalAuthorizedKey(key))}); err != nil {
		return 1, err
	}
	if err := vault.SaveContext(ctx, path, v, secret); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Updated encrypted server pins only; connection identity and usage were preserved.")
	return 0, nil
}
