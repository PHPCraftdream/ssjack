#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -gt 1 ]]; then
    printf 'Usage: update-ssjack.sh [candidate]\n' >&2
    exit 1
fi
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        args=()
        if [[ $# -eq 1 ]]; then args=(-CandidatePath "$(cygpath -w "$1")"); fi
        exec powershell.exe -NoLogo -NoProfile -File "$(cygpath -w "$root/update-ssjack.ps1")" "${args[@]}"
        ;;
esac

build="$root/build"
candidate="${1:-$build/ui-next/ssjack}"
if [[ ! -f "$build/ssjack" || ! -f "$candidate" || -L "$candidate" ]]; then
    printf 'The development installation and regular candidate must exist.\n' >&2
    exit 1
fi
candidate="$(cd -- "$(dirname -- "$candidate")" && pwd -P)/$(basename -- "$candidate")"
if [[ "$candidate" == "$build/ssjack" ]]; then
    printf 'Candidate and installed executable must differ.\n' >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    expected="$(sha256sum "$candidate")"
elif command -v shasum >/dev/null 2>&1; then
    expected="$(shasum -a 256 "$candidate")"
else
    printf 'SHA256 tooling is required.\n' >&2
    exit 1
fi
exec sh "$root/install.sh" --candidate "$candidate" --sha256 "${expected%% *}" --install-dir "$build"
