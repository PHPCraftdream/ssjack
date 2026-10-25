package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"storagehost/internal/keyfile"
	"storagehost/internal/remote"
	"storagehost/internal/rotation"
	"storagehost/internal/vault"
)

func runRotation(ctx context.Context, path, name string) (int, error) {
	if err := vault.ValidateName(name); err != nil {
		return 1, err
	}
	v, secret, err := openManagedVault(path)
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	defer v.Close()
	target, exists := v.Targets[name]
	if !exists {
		return 1, errors.New("credential record does not exist")
	}
	config, err := target.ClientConfig()
	if err != nil {
		return 1, err
	}
	probeCtx, stopProbe := context.WithTimeout(ctx, 30*time.Second)
	err = remote.Check(probeCtx, target.Address, config)
	stopProbe()
	if err != nil {
		return 1, err
	}
	oldPublic, err := keyfile.PublicSSH(target.PrivateKey)
	if err != nil {
		return 1, err
	}
	recoverySecret, err := confirmedSecretFor("new key recovery secret")
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Deriving the replacement key with the fixed memory-hard profile. The recovery file uses this new secret, not necessarily the vault secret.")
	encoded, public, private, err := keyfile.GenerateRecovery(recoverySecret)
	clear(recoverySecret)
	if err != nil {
		return 1, err
	}
	defer clear(private)
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	oldKey, _, _, _, err := ssh.ParseAuthorizedKey(oldPublic)
	if err != nil {
		return 1, err
	}
	newKey, _, _, _, err := ssh.ParseAuthorizedKey(public)
	if err != nil {
		return 1, err
	}
	err = rotation.Apply(ctx, target, private, public, rotation.Operations{
		Preserve: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			previous, err := vault.Snapshot(path, v)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Previous encrypted database: %q\n", previous)
			recovery, err := vault.RecoveryPath(path, "new-key-"+name)
			if err != nil {
				return err
			}
			if err := writeNewFile(recovery, encoded, 0600); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "New encrypted key recovery file: %q\n", recovery)
			return nil
		},
		Confirm: func() error {
			fmt.Fprintln(os.Stderr, "Old CLIENT key:", ssh.FingerprintSHA256(oldKey))
			fmt.Fprintln(os.Stderr, "New CLIENT key:", ssh.FingerprintSHA256(newKey))
			fmt.Fprintln(os.Stderr, "This adds a public key to the remote POSIX account's existing ~/.ssh/authorized_keys. Option-bearing key entries are refused. The old key will NOT be removed.")
			return confirmValue("Type the credential name to authorize remote key addition: ", name)
		},
		Add: func(ctx context.Context, original vault.Target, newPublic []byte) error {
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return remote.AddAuthorizedKey(ctx, original.Address, config, oldPublic, newPublic)
		},
		Verify: func(ctx context.Context, replacement vault.Target) error {
			newConfig, err := replacement.ClientConfig()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return remote.Check(ctx, replacement.Address, newConfig)
		},
		Commit: func(ctx context.Context, replacement vault.Target) error {
			if err := v.ReplaceKey(name, replacement.PrivateKey); err != nil {
				return err
			}
			return vault.SaveContext(ctx, path, v, secret)
		},
	})
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "New login verified and encrypted credential switched. The OLD remote public key remains authorized; retire it manually only after checking all intended clients. Recovery files were retained.")
	return 0, nil
}
