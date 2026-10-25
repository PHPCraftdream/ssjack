package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

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
