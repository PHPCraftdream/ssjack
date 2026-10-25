#!/bin/sh
set -eu

repository='PHPCraftdream/ssjack'
version=''
install_dir='/usr/local/bin'

usage() {
    printf '%s\n' 'Usage: sh install.sh [--version <tag>] [--install-dir <absolute-directory>]'
}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || fail 'Missing version tag.'
            version=$2
            shift 2
            ;;
        --install-dir)
            [ "$#" -ge 2 ] || fail 'Missing installation directory.'
            install_dir=$2
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; fail 'Unknown installer option.' ;;
    esac
done

case "$(uname -s)" in
    Linux) os='linux' ;;
    Darwin) os='darwin' ;;
    *) fail 'Unsupported OS. On Windows, use install.ps1.' ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch='amd64' ;;
    aarch64|arm64) arch='arm64' ;;
    *) fail 'Unsupported CPU architecture; expected amd64 or arm64.' ;;
esac
case "$install_dir" in
    /*) ;;
    *) fail 'The installation directory must be absolute.' ;;
esac
command -v curl >/dev/null 2>&1 || fail 'curl is required.'

if [ -z "$version" ]; then
    resolved=$(curl --fail --silent --show-error --location --head \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 180 --output /dev/null --write-out '%{url_effective}' \
        "https://github.com/$repository/releases/latest") || fail 'Could not resolve the latest release.'
    prefix="https://github.com/$repository/releases/tag/"
    case "$resolved" in
        "$prefix"*) version=${resolved#"$prefix"} ;;
        *) fail 'Latest release did not resolve to the expected repository.' ;;
    esac
fi
printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9][A-Za-z0-9.-]*)?$' || fail 'Invalid version tag.'

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        result=$(sha256sum "$1") || return 1
    elif command -v shasum >/dev/null 2>&1; then
        result=$(shasum -a 256 "$1") || return 1
    else
        printf 'sha256sum or shasum is required.\n' >&2
        return 1
    fi
    printf '%s\n' "${result%% *}" | tr 'A-F' 'a-f'
}

probe() {
    output=$("$1" --help 2>&1) || return 1
    case "$output" in
        *'Usage: ssjack '*) return 0 ;;
        *) return 1 ;;
    esac
}

[ ! -L "$install_dir" ] || fail 'The installation directory must not be a symlink.'
mkdir -p "$install_dir" || fail 'Cannot create the installation directory; use an explicitly authorized writable destination.'
install_dir=$(cd "$install_dir" && pwd -P)
target="$install_dir/ssjack"
if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
    fail 'The installed executable must be a regular file, not a symlink.'
fi
lock="$install_dir/.ssjack-install.lock"
mkdir "$lock" 2>/dev/null || fail 'Installer lock exists; confirm no installer is active before removing a stale lock.'
stage=''
backup=''
failed=''
old_moved=false
new_installed=false
committed=false
asset="ssjack_${os}_${arch}"

cleanup() {
    code=$?
    trap - EXIT HUP INT TERM
    if ! $committed; then
        if $new_installed && [ -f "$target" ]; then
            if mv "$target" "$failed"; then
                printf 'Failed candidate retained: %s\n' "$failed" >&2
            else
                printf 'Could not move failed candidate away from the installed path.\n' >&2
                code=1
            fi
        fi
        if $old_moved; then
            if [ ! -e "$target" ] && [ ! -L "$target" ] && mv "$backup" "$target"; then
                printf 'Previous executable restored.\n' >&2
            else
                printf 'Rollback could not restore the original path. Backup: %s\n' "$backup" >&2
                code=1
            fi
        fi
    fi
    if [ -n "$stage" ]; then
        rm -f "$stage/$asset" "$stage/SHA256SUMS" || code=1
        rmdir "$stage" || code=1
    fi
    rmdir "$lock" || code=1
    exit "$code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
stage=$(mktemp -d "$install_dir/.ssjack-install.XXXXXXXX")
base="https://github.com/$repository/releases/download/$version"
for file in "$asset" SHA256SUMS; do
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 180 --max-filesize 134217728 \
        --output "$stage/$file" "$base/$file" || fail 'Release download failed; the installed executable was not replaced.'
done
[ "$(wc -c < "$stage/SHA256SUMS")" -le 65536 ] || fail 'Checksum manifest is too large.'
expected=$(awk -v name="$asset" '
    NF == 2 && ($2 == name || $2 == "*" name) { count++; hash = $1 }
    END { if (count != 1) exit 1; print hash }
' "$stage/SHA256SUMS") || fail 'The checksum manifest must contain exactly one entry for the binary.'
printf '%s\n' "$expected" | grep -Eq '^[0-9A-Fa-f]{64}$' || fail 'Invalid SHA-256 checksum.'
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
[ "$(hash_file "$stage/$asset")" = "$expected" ] || fail 'SHA-256 mismatch; refusing to execute or install the download.'
chmod 0755 "$stage/$asset"
probe "$stage/$asset" || fail 'The verified download failed the ssjack --help check.'
[ "$(hash_file "$stage/$asset")" = "$expected" ] || fail 'Candidate changed during verification.'
if [ -f "$target" ] && [ "$(hash_file "$target")" = "$expected" ]; then
    printf 'Already installed: %s (%s)\n' "$target" "$version"
    exit 0
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)-${stage##*.}"
backup="$target.previous-$stamp"
failed="$target.failed-$stamp"
[ ! -e "$backup" ] && [ ! -L "$backup" ] && [ ! -e "$failed" ] && [ ! -L "$failed" ] || fail 'Backup path conflict.'
if [ -f "$target" ]; then
    mv "$target" "$backup"
    old_moved=true
fi
mv "$stage/$asset" "$target"
new_installed=true
[ "$(hash_file "$target")" = "$expected" ] || fail 'Installed executable hash mismatch.'
probe "$target" || fail 'Installed executable failed its help check.'
committed=true
printf 'Installed: %s\nVersion: %s\nSHA256: %s\n' "$target" "$version" "$expected"
if $old_moved; then printf 'Previous executable retained: %s\n' "$backup"; fi
printf 'No process was stopped. Restart ssjack to use the installed executable.\n'
case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) printf 'Add this directory to PATH before using ssjack by name: %s\n' "$install_dir" ;;
esac
