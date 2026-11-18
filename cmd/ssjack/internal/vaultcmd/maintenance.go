package vaultcmd

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/credential"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/keys"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/terminal"
	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
	"github.com/PHPCraftdream/ssjack/internal/diagnostic"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/legacy"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/rotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func confirmValue(prompt, expected string) error {
	value, err := terminal.Secret(prompt)
	if err != nil {
		return err
	}
	defer clear(value)
	if subtle.ConstantTimeCompare(value, []byte(expected)) != 1 {
		return errors.New("confirmation did not match; operation cancelled")
	}
	return nil
}

// RunVaultMaintenance executes the `vault` maintenance surface:
// migrate, init [--generate-key], passwd, upgrade, backup, check, restore.
func RunVaultMaintenance(ctx context.Context, path, profile string, args []string) (int, error) {
	if len(args) == 2 && args[0] == "migrate" {
		return runLegacyMigration(ctx, path, profile, args[1])
	}
	if len(args) == 2 && args[0] == "init" && args[1] == "--generate-key" {
		return runInitProfileWithKey(ctx, path, profile, true)
	}
	if len(args) == 1 && args[0] == "init" {
		return runInitProfile(ctx, path, profile)
	}
	if len(args) == 1 && args[0] == "upgrade" {
		return runVaultUpgrade(ctx, path)
	}
	if len(args) == 1 && args[0] == "passwd" {
		return RunVaultCommand(ctx, path, args)
	}
	if len(args) != 2 || (args[0] != "backup" && args[0] != "check" && args[0] != "restore") {
		return 1, errors.New("usage: ssjack vault init|passwd|upgrade|backup FILE|check FILE|restore FILE; use ssjack help vault")
	}
	if args[0] == "backup" {
		if err := keys.RequireNewPath(args[1]); err != nil {
			return 1, err
		}
		password, err := startup.ReadVaultPassword(ctx, "Vault secret: ", terminal.Secret)
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
	password, err := terminal.Secret("Backup secret: ")
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
		current, err = startup.ReadVaultPassword(ctx, "Current vault secret: ", terminal.Secret)
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

// runVaultUpgrade converts a v1 database to the opaque v2 format after
// explicit confirmation, preserving the original as a recovery copy.
func runVaultUpgrade(ctx context.Context, path string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	password, err := startup.ReadVaultPassword(ctx, "Vault secret: ", terminal.Secret)
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

// runLegacyMigration imports one connection from a legacy plaintext
// configuration into an encrypted profile without modifying the source.
func runLegacyMigration(ctx context.Context, destination, profile, source string) (int, error) {
	if err := vault.ValidateName(profile); err != nil {
		return 1, err
	}
	var v *vault.Vault
	var secret []byte
	var err error
	fresh := false
	if _, err = os.Lstat(destination); os.IsNotExist(err) {
		if err := keys.RequireNewPath(destination); err != nil {
			return 1, err
		}
		secret, err = terminal.ConfirmedSecretFor("database secret")
		v = vault.New()
		fresh = true
	} else if err == nil {
		v, secret, err = openManagedVaultForWrite(ctx, destination)
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
	usageInput, err := terminal.VisibleInput("Usage both/human/agent (Enter for both): ", true)
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
	if err := terminal.ConfirmVisibleValue("Type the destination profile name to confirm: ", profile); err != nil {
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

// RunSafetyCommand dispatches the diagnostic and credential-safety surface:
// doctor, check NAME, hostkey show/replace, and rotate NAME.
func RunSafetyCommand(ctx context.Context, path string, args []string) (int, error) {
	if len(args) == 1 && args[0] == "doctor" {
		return runDoctor(ctx, path)
	}
	if len(args) == 2 && args[0] == "check" {
		if err := credential.ValidateCredentialSelection(args[1]); err != nil {
			return 1, err
		}
		config, address, name, err := credential.ReadVaultCredential(ctx, path, args[1], "")
		if err != nil {
			return 1, err
		}
		if err := remote.Check(ctx, address, config); err != nil {
			return 1, err
		}
		fmt.Fprintf(os.Stdout, "OK %s: server pin, SSH authentication, and session opening verified; no remote command was executed.\n", name)
		return 0, nil
	}
	if len(args) > 0 && args[0] == "hostkey" {
		return runHostKey(ctx, path, args[1:])
	}
	if len(args) == 2 && args[0] == "rotate" {
		return runRotation(ctx, path, args[1])
	}
	return 1, errors.New("invalid command arguments; use ssjack help COMMAND")
}

func runDoctor(ctx context.Context, path string) (int, error) {
	fmt.Fprintln(os.Stdout, buildinfo.String())
	executable, err := os.Executable()
	if err != nil {
		return 1, err
	}
	root, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	resolved, _ := exec.LookPath("ssjack")
	findings := diagnostic.Inspect(diagnostic.Paths{Root: root, Vault: path, Executable: executable, PathExecutable: resolved})
	for _, finding := range findings {
		fmt.Fprintf(os.Stdout, "%s %-18s %s\n", finding.Status, finding.Check, finding.Detail)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return 1, errors.New("vault is unavailable; create it with ssjack vault init")
	}
	secret, err := startup.ReadVaultPassword(ctx, "Vault secret for full validation: ", terminal.Secret)
	if err != nil {
		return 1, err
	}
	v, err := vault.Load(path, secret)
	clear(secret)
	if err != nil {
		return 1, err
	}
	defer v.Close()
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	fmt.Fprintf(os.Stdout, "OK vault integrity    verified %d records; 4 Argon2id operations at %d KiB each, %d AES-GCM data layers\n", len(v.Targets), keyfile.MemoryKiB, keyfile.Layers)
	fmt.Fprintln(os.Stdout, "WARN UI compatibility requires a harness supporting function-hook render plugins; no harness was launched")
	if err := diagnostic.Failed(findings); err != nil {
		return 1, err
	}
	return 0, nil
}

// refuseActiveRotation runs before any remote effect: the final save would
// reject an active journal after the legacy flow had already added a key.
func refuseActiveRotation(v *vault.Vault) error {
	if vault.RotationActive(v.Rotation) {
		return errors.New("a key rotation is active in this vault; resolve it with the owner rotate-key flow")
	}
	return nil
}

// runRotation replaces the client private key of a credential through a
// verified remote authorized_keys addition, keeping the old key authorized.
func runRotation(ctx context.Context, path, name string) (int, error) {
	if err := credential.ValidateCredentialSelection(name); err != nil {
		return 1, err
	}
	v, secret, err := openManagedVaultForWrite(ctx, path)
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	defer v.Close()
	if err := refuseActiveRotation(v); err != nil {
		return 1, err
	}
	name, err = credential.ChooseCredential(v, name)
	if err != nil {
		return 1, err
	}
	target, exists := v.Targets[name]
	if !exists {
		return 1, errors.New("credential record does not exist")
	}
	if len(target.Password) != 0 {
		return 1, errors.New("key rotation requires a private-key account; password accounts are not contacted")
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
	recoverySecret, err := terminal.ConfirmedSecretFor("new key recovery secret")
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
			if err := keys.WriteNewFile(recovery, encoded, 0600); err != nil {
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
			return vault.SaveUnlocked(ctx, path, v)
		},
	})
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "New login verified and encrypted credential switched. The OLD remote public key remains authorized; retire it manually only after checking all intended clients. Recovery files were retained.")
	return 0, nil
}
