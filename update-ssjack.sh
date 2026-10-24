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
target="$build/ssjack"
candidate="${1:-$build/ui-next/ssjack}"
lock="$build/.ssjack-update.lock.d"
stage=''
backup=''
old_moved=false
new_installed=false
committed=false

hash_file() {
    local result
    if command -v sha256sum >/dev/null 2>&1; then
        result="$(sha256sum "$1")"
    elif command -v shasum >/dev/null 2>&1; then
        result="$(shasum -a 256 "$1")"
    else
        printf 'SHA256 tooling is required.\n' >&2
        return 1
    fi
    printf '%s\n' "${result%% *}"
}

probe() {
    local output
    if ! output="$("$1" --help 2>&1)"; then
        printf 'Candidate failed the ssjack --help check.\n' >&2
        return 1
    fi
    case "$output" in
        *'Usage: ssjack '*) ;;
        *) printf 'Candidate is not recognized as ssjack.\n' >&2; return 1 ;;
    esac
}

cleanup() {
    local code=$?
    trap - EXIT HUP INT TERM
    if $old_moved && ! $committed; then
        if $new_installed && [[ -e "$target" ]]; then
            mv "$target" "$target.failed-${backup##*previous-}" || code=1
        fi
        if [[ ! -e "$target" && ! -L "$target" ]] && mv "$backup" "$target"; then
            printf 'Previous executable restored.\n' >&2
        else
            printf 'Rollback could not restore the original path. Previous executable: %s\n' "$backup" >&2
            code=1
        fi
    fi
    if [[ -n "$stage" && -f "$stage" ]]; then rm -f "$stage"; fi
    rmdir "$lock" || code=1
    exit "$code"
}

if [[ ! -f "$candidate" || -L "$candidate" || ! -f "$target" || -L "$target" || -L "$build" ]]; then
    printf 'Candidate and installed executable must be regular files under a regular build directory.\n' >&2
    exit 1
fi
candidate="$(cd -- "$(dirname -- "$candidate")" && pwd)/$(basename -- "$candidate")"
if [[ "$candidate" == "$target" ]]; then
    printf 'Candidate and installed executable must be different files.\n' >&2
    exit 1
fi
if ! mkdir "$lock"; then
    printf 'Update lock exists. Confirm no updater is running before removing a stale lock.\n' >&2
    exit 1
fi
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
expected_hash="$(hash_file "$candidate")"
old_hash="$(hash_file "$target")"
if [[ "$expected_hash" == "$old_hash" ]]; then
    printf 'Already up to date: %s\nSHA256: %s\n' "$target" "$expected_hash"
    exit 0
fi
stage="$(mktemp "$build/.ssjack-update.XXXXXXXX")"
cp "$candidate" "$stage"
chmod u+x "$stage"
[[ "$(hash_file "$stage")" == "$expected_hash" ]]
probe "$stage"
[[ "$(hash_file "$stage")" == "$expected_hash" ]]
backup="$build/ssjack.previous-$(date -u +%Y%m%dT%H%M%SZ)-${stage##*.}"
[[ ! -e "$backup" && ! -L "$backup" ]]
mv "$target" "$backup"
old_moved=true
mv "$stage" "$target"
new_installed=true
[[ "$(hash_file "$target")" == "$expected_hash" ]]
probe "$target"
committed=true
printf 'Updated: %s\nPrevious executable: %s\nPrevious SHA256: %s\nInstalled SHA256: %s\n' "$target" "$backup" "$old_hash" "$expected_hash"
printf 'No process was stopped. Restart ssjack to use the installed version.\n'
