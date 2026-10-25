package remote

import (
	"bytes"
	"context"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
)

const authorizedKeyScript = `set -eu
umask 077
IFS= read -r old
IFS= read -r new
oldtype=${old%% *}
oldblob=${old#* }
newtype=${new%% *}
newblob=${new#* }
directory=$HOME/.ssh
file=$directory/authorized_keys
[ -d "$directory" ] && [ ! -L "$directory" ]
[ -f "$file" ] && [ ! -L "$file" ]
lock=$directory/.ssjack-rotate.lock
mkdir "$lock"
trap 'rmdir "$lock"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
awk -v ot="$oldtype" -v ob="$oldblob" -v nt="$newtype" -v nb="$newblob" '
    index($0, ob) { found=1; if ($1 != ot || $2 != ob) bad=1 }
    index($0, nb) { if ($1 != nt || $2 != nb) bad=1 }
    END { if (!found || bad) exit 1 }
' "$file"
chmod 700 "$directory"
chmod 600 "$file"
if ! grep -Fqx -- "$new" "$file"; then
    printf '\n%s\n' "$new" >> "$file"
fi
`

func canonicalPublic(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 16384 {
		return nil, errors.New("invalid public key size")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one bare client public key")
	}
	if _, certificate := key.(*ssh.Certificate); certificate {
		return nil, errors.New("automatic certificate rotation is not supported")
	}
	return ssh.MarshalAuthorizedKey(key), nil
}

// AddAuthorizedKey keeps the old line and refuses option-bearing key entries.
func AddAuthorizedKey(ctx context.Context, address string, config *ssh.ClientConfig, oldPublic, newPublic []byte) error {
	oldKey, err := canonicalPublic(oldPublic)
	if err != nil {
		return err
	}
	newKey, err := canonicalPublic(newPublic)
	if err != nil {
		return err
	}
	if bytes.Equal(oldKey, newKey) {
		return errors.New("rotation requires a different public key")
	}
	if config == nil || config.HostKeyCallback == nil || len(config.Auth) == 0 {
		return errors.New("rotation requires verified credentials")
	}
	client, closeClient, err := connectSSH(ctx, address, config)
	if err != nil {
		return err
	}
	defer closeClient()
	session, err := client.NewSession()
	if err != nil {
		return sshStageError(ctx, "failed to open key installation session")
	}
	defer session.Close()
	payload := append(append([]byte(nil), oldKey...), newKey...)
	session.Stdin = bytes.NewReader(payload)
	session.Stdout, session.Stderr = io.Discard, io.Discard
	if err := session.Run(authorizedKeyScript); err != nil {
		return sshStageError(ctx, "public-key installation failed; option-bearing or nonstandard authorized_keys require manual rotation")
	}
	return ctx.Err()
}
