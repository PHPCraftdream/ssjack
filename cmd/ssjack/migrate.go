package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/legacy"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func runLegacyMigration(ctx context.Context, destination, profile, source string) (int, error) {
	if err := vault.ValidateName(profile); err != nil {
		return 1, err
	}
	var v *vault.Vault
	var secret []byte
	var err error
	fresh := false
	if _, err = os.Lstat(destination); os.IsNotExist(err) {
		if err := requireNewPath(destination); err != nil {
			return 1, err
		}
		secret, err = confirmedSecretFor("database secret")
		v = vault.New()
		fresh = true
	} else if err == nil {
		v, secret, err = openManagedVault(destination)
	}
	if err != nil {
		clear(secret)
		return 1, err
	}
	defer clear(secret)
	defer v.Close()
	if _, exists := v.Targets[profile]; exists {
		return 1, errors.New("profile already exists; migration never overwrites it")
	}
	config, err := remote.LoadConfig(source)
	if err != nil {
		return 1, err
	}
	var names []string
	for name := range config.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	selected := names[0]
	if len(names) > 1 {
		fmt.Fprintln(os.Stderr, "Legacy connection labels:")
		for _, name := range names {
			fmt.Fprintf(os.Stderr, "  %q\n", name)
		}
		selected, err = credentialField("Legacy connection to import", "", false)
		if err != nil {
			return 1, err
		}
	}
	old, exists := config.Targets[selected]
	if !exists {
		return 1, errors.New("legacy connection does not exist")
	}
	pins, err := legacy.HostPins(old.KnownHosts, old.Address)
	if err != nil {
		return 1, err
	}
	private, err := readImportedPrivate(config.Keys[old.Key])
	if err != nil {
		return 1, err
	}
	defer clear(private)
	usageInput, err := readVisibleInput("Usage both/human/agent (Enter for both): ", true)
	if err != nil {
		return 1, err
	}
	usage := "both"
	if len(usageInput) != 0 {
		usage = strings.TrimSpace(string(usageInput))
	}
	clear(usageInput)
	target := vault.Target{Address: old.Address, User: old.User, PrivateKey: private, HostKeys: pins, Usage: usage}
	if err := target.Validate(); err != nil {
		return 1, err
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Importing connection settings, private key bytes, and already trusted server pins into encrypted profile:", profile)
	fmt.Fprintln(os.Stderr, "No source file will be deleted. Old plaintext metadata and weaker key copies remain until separately retired.")
	if err := confirmVisibleValue("Type the destination profile name to confirm: ", profile); err != nil {
		return 1, err
	}
	if !fresh {
		previous, err := vault.Snapshot(destination, v)
		if err != nil {
			return 1, err
		}
		fmt.Fprintf(os.Stderr, "Previous encrypted database retained: %q\n", previous)
	}
	v.Targets[profile] = target
	if fresh {
		err = vault.CreateWithRecords(ctx, destination, v, secret)
	} else {
		err = vault.SaveUnlocked(ctx, destination, v)
	}
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Profile migrated. Normal ssh/run commands use only the encrypted database; originals were not changed.")
	return 0, nil
}
