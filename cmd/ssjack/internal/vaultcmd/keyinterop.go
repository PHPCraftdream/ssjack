package vaultcmd

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/keys"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/terminal"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// readImportedPrivate loads a foreign private key file (OpenSSH, PEM, or
// ssjack), prompting for its passphrase when required, and returns the
// decrypted in-memory key bytes.
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
		password, err = terminal.Secret("Imported key passphrase: ")
		if err != nil {
			return nil, err
		}
	} else {
		fmt.Fprintln(os.Stderr, "Source key is unencrypted. The vault will encrypt its copy; the source file will remain unchanged.")
	}
	defer clear(password)
	return keyfile.ImportSSH(data, password)
}

// exportVaultKey writes an encrypted OpenSSH copy of an in-memory private
// key after refusing existing outputs and passphrases equal to the vault
// secret.
func exportVaultKey(ctx context.Context, path string, plaintext, vaultSecret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := keys.RequireNewPath(path); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "OpenSSH export uses standard protection, not the ssjack Argon2id/AES-layer profile. Use a different passphrase: reusing the vault secret gives attackers a cheaper way to guess that secret.")
	if err := ctx.Err(); err != nil {
		return err
	}
	password, err := terminal.ConfirmedSecretFor("OpenSSH passphrase")
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
	return keys.WriteNewFile(path, encoded, 0600)
}

// runHostKey implements `hostkey show NAME` and `hostkey replace NAME FILE`.
func runHostKey(ctx context.Context, path string, args []string) (int, error) {
	if !((len(args) == 2 && args[0] == "show") || (len(args) == 3 && args[0] == "replace")) {
		return 1, errors.New("usage: ssjack hostkey show NAME | replace NAME FILE; use ssjack help hostkey")
	}
	if err := vault.ValidateName(args[1]); err != nil {
		return 1, err
	}
	open := openManagedVault
	if args[0] == "replace" {
		open = openManagedVaultForWrite
	}
	v, secret, err := open(ctx, path)
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
	if err := vault.SaveUnlocked(ctx, path, v); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Updated encrypted server pins only; connection identity and usage were preserved.")
	return 0, nil
}

func policyList(values []string) string {
	if len(values) == 0 {
		return "<safe compiled defaults>"
	}
	return strings.Join(values, ",")
}

// RunPolicy implements `policy show|edit` for the selected profile.
func RunPolicy(ctx context.Context, path, profile string, args []string) (int, error) {
	if len(args) != 1 || (args[0] != "show" && args[0] != "edit") {
		return 1, errors.New("usage: ssjack [-p PROFILE] policy show|edit")
	}
	open := openManagedVault
	if args[0] == "edit" {
		open = openManagedVaultForWrite
	}
	v, secret, err := open(ctx, path)
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	defer v.Close()
	target, exists := v.Targets[profile]
	if !exists {
		return 1, errors.New("selected profile does not exist")
	}
	if args[0] == "show" {
		fmt.Fprintln(os.Stdout, "Host keys:", policyList(target.SSHPolicy.HostKeys))
		fmt.Fprintln(os.Stdout, "Key exchanges:", policyList(target.SSHPolicy.KeyExchanges))
		fmt.Fprintln(os.Stdout, "Ciphers:", policyList(target.SSHPolicy.Ciphers))
		fmt.Fprintln(os.Stdout, "MACs:", policyList(target.SSHPolicy.MACs))
		return 0, nil
	}
	supported := ssh.SupportedAlgorithms()
	policy := target.SSHPolicy
	fields := []struct {
		name    string
		value   *[]string
		allowed []string
	}{
		{"Host keys", &policy.HostKeys, supported.HostKeys},
		{"Key exchanges", &policy.KeyExchanges, supported.KeyExchanges},
		{"Ciphers", &policy.Ciphers, supported.Ciphers},
		{"MACs", &policy.MACs, supported.MACs},
	}
	fmt.Fprintln(os.Stderr, "Only supported safe SSH algorithms are accepted. Enter keeps the value; type default to reset it. Input is hidden; no policy values are passed in argv.")
	for _, field := range fields {
		fmt.Fprintln(os.Stderr, field.name, "supported:", strings.Join(field.allowed, ","))
		input, err := terminal.TerminalInput(field.name+" preferences: ", true)
		if err != nil {
			return 1, err
		}
		text := strings.TrimSpace(string(input))
		clear(input)
		if text == "" {
			continue
		}
		if text == "default" {
			*field.value = nil
			continue
		}
		values := strings.Split(text, ",")
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
		*field.value = values
	}
	if err := v.ReplacePolicy(profile, policy); err != nil {
		return 1, err
	}
	if err := confirmValue("Type the profile name to save this encrypted policy: ", profile); err != nil {
		return 1, err
	}
	if err := vault.SaveUnlocked(ctx, path, v); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Saved SSH algorithm preferences inside the encrypted profile. Server pins and private key were not changed.")
	return 0, nil
}

func writeProfileSummary(output io.Writer, name string, target vault.Target) error {
	if _, err := fmt.Fprintf(output, "Profile: %s\nAddress: %q\nUser: %q\nUsage: %s\n", name, target.Address, target.User, target.EffectiveUsage()); err != nil {
		return err
	}
	for _, encoded := range target.HostKeys {
		key, err := vault.ParseHostKey([]byte(encoded))
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(output, "Server key:", ssh.FingerprintSHA256(key)); err != nil {
			return err
		}
	}
	return nil
}

// saveProfileWithInstructions persists the encrypted database and only then
// displays the generated public key installation instructions.
func saveProfileWithInstructions(ctx context.Context, save func() error, output io.Writer, public []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := save(); err != nil {
		return err
	}
	if len(public) != 0 {
		if err := writeKeyInstallInstructions(output, public); err != nil {
			return fmt.Errorf("profile saved, but public-key instructions could not be displayed: %w", err)
		}
	}
	return nil
}

func writeKeyInstallInstructions(output io.Writer, public []byte) error {
	key, _, options, rest, err := ssh.ParseAuthorizedKey(public)
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("invalid generated public key")
	}
	if _, certificate := key.(*ssh.Certificate); certificate {
		return errors.New("generated key must not be a certificate")
	}
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	command := strings.ReplaceAll(keyInstallCommand, "@PUBLIC_IDENTITY@", canonical)
	_, err = fmt.Fprintf(output, "Public key:\n%s\n\nRun this on the destination as the intended SSH user (not root unless that is the intended account). It does not create the user. PTY must also be allowed by the SSH server.\n\n%s", canonical, command)
	return err
}

const keyInstallCommand = `sh -eu <<'SSJACK_INSTALL_KEY'
umask 077
[ ! -L "$HOME/.ssh" ] || { echo 'Refusing a linked .ssh directory' >&2; exit 1; }
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
file="$HOME/.ssh/authorized_keys"
[ ! -L "$file" ] || { echo 'Refusing linked authorized_keys' >&2; exit 1; }
[ ! -e "$file" ] || [ -f "$file" ] || { echo 'Expected regular authorized_keys' >&2; exit 1; }
lock="$HOME/.ssh/.ssjack-key-install.lock"
mkdir "$lock" || { echo 'Key installation is locked; inspect before retrying' >&2; exit 1; }
trap 'rmdir "$lock"' 0
trap 'exit 1' HUP INT TERM
if [ ! -e "$file" ]; then
    (set -C; : > "$file")
fi
identity='@PUBLIC_IDENTITY@'
key="restrict,pty $identity"
if matches=$(grep -F -c -- "$identity" "$file"); then
    :
else
    status=$?
    [ "$status" -eq 1 ] || exit "$status"
fi
if [ "$matches" -ne 0 ]; then
    if [ "$matches" -ne 1 ] || ! grep -Fqx -- "$key" "$file"; then
        echo 'Key already exists with other options; review it without dropping restrictions' >&2
        exit 1
    fi
else
    printf '\n%s\n' "$key" >> "$file"
fi
chmod 600 "$file"
echo 'Public key installed with restrict,pty. Existing keys were retained.'
SSJACK_INSTALL_KEY
`
