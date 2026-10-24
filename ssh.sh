#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ssh_bin="$(cygpath -u "${SYSTEMROOT:?SYSTEMROOT is not set}")/System32/OpenSSH/ssh.exe"

cd -- "$root"
exec "$ssh_bin" -F .ssh/config storagehost "$@"
