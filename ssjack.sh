#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) binary="$root/build/ssjack.exe" ;;
    *) binary="$root/build/ssjack" ;;
esac

if [[ ! -x "$binary" ]]; then
    printf 'Build ssjack first; see SSJACK.md.\n' >&2
    exit 1
fi

exec "$binary" "$@"
