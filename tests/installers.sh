#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="${1:?pass the native installer fixture executable}"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/ssjack-installer-test.XXXXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT
mkdir "$temporary/tools"
export SSJACK_FIXTURE_BINARY="$fixture"
export SSJACK_REAL_UNAME="$(command -v uname)"
export SSJACK_FAKE_OS="$(uname -s)"
export SSJACK_FAKE_ARCH="$(uname -m)"
export SSJACK_CURL_CALLS="$temporary/curl-calls"
export SSJACK_INSTALL_TEST_MARKER="$temporary/executed"
export SSJACK_FIXTURE_MODE='good'

cat > "$temporary/tools/uname" <<'MOCK'
#!/bin/sh
case "$1" in
    -s) printf '%s\n' "$SSJACK_FAKE_OS" ;;
    -m) printf '%s\n' "$SSJACK_FAKE_ARCH" ;;
    *) exec "$SSJACK_REAL_UNAME" "$@" ;;
esac
MOCK
cat > "$temporary/tools/curl" <<'MOCK'
#!/bin/sh
set -eu
printf 'request\n' >> "$SSJACK_CURL_CALLS"
out=''
url=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) out=$2; shift 2 ;;
        https://*) url=$1; shift ;;
        *) shift ;;
    esac
done
[ "$SSJACK_FIXTURE_MODE" != 'download-error' ] || exit 22
case "$url" in
    */releases/latest)
        printf '%s' 'https://github.com/PHPCraftdream/ssjack/releases/tag/v0.0.0-test'
        exit 0
        ;;
esac
file=${url##*/}
if [ "$file" = SHA256SUMS ]; then
    if command -v sha256sum >/dev/null 2>&1; then value=$(sha256sum "$SSJACK_FIXTURE_BINARY"); else value=$(shasum -a 256 "$SSJACK_FIXTURE_BINARY"); fi
    value=${value%% *}
    [ "$SSJACK_FIXTURE_MODE" != badsum ] || value='0000000000000000000000000000000000000000000000000000000000000000'
    if [ "$SSJACK_FIXTURE_MODE" = missing ]; then printf '%s  other-file\n' "$value" > "$out"; exit 0; fi
    case "$SSJACK_FAKE_OS" in Linux) os=linux ;; Darwin) os=darwin ;; *) exit 22 ;; esac
    case "$SSJACK_FAKE_ARCH" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) exit 22 ;; esac
    printf '%s  ssjack_%s_%s\n' "$value" "$os" "$arch" > "$out"
    if [ "$SSJACK_FIXTURE_MODE" = duplicate ]; then printf '%s  ssjack_%s_%s\n' "$value" "$os" "$arch" >> "$out"; fi
else
    cp "$SSJACK_FIXTURE_BINARY" "$out"
fi
MOCK
chmod +x "$temporary/tools/uname" "$temporary/tools/curl"
export PATH="$temporary/tools:$PATH"

hash_file() {
    local value
    if command -v sha256sum >/dev/null 2>&1; then value="$(sha256sum "$1")"; else value="$(shasum -a 256 "$1")"; fi
    printf '%s\n' "${value%% *}"
}

install() {
    sh "$root/install.sh" --version v0.0.0-test --install-dir "$1"
}

fresh="$temporary/fresh install"
install "$fresh"
[[ "$(hash_file "$fresh/ssjack")" == "$(hash_file "$fixture")" ]]
install "$fresh"
[[ "$(find "$fresh" -name 'ssjack.previous-*' | wc -l | tr -d ' ')" == 0 ]]
[[ ! -e "$fresh/.ssjack-install.lock" ]]

update="$temporary/update"
mkdir "$update"
printf 'previous executable' > "$update/ssjack"
old="$(hash_file "$update/ssjack")"
install "$update"
backup="$(find "$update" -name 'ssjack.previous-*')"
[[ -f "$backup" && "$(hash_file "$backup")" == "$old" ]]

for mode in badsum duplicate missing download-error; do
    destination="$temporary/$mode"
    mkdir "$destination"
    printf 'previous executable' > "$destination/ssjack"
    before="$(hash_file "$destination/ssjack")"
    rm -f "$SSJACK_INSTALL_TEST_MARKER"
    export SSJACK_FIXTURE_MODE="$mode"
    if install "$destination"; then printf 'Expected failure: %s\n' "$mode" >&2; exit 1; fi
    [[ "$(hash_file "$destination/ssjack")" == "$before" ]]
    [[ ! -e "$SSJACK_INSTALL_TEST_MARKER" && ! -e "$destination/.ssjack-install.lock" ]]
done
export SSJACK_FIXTURE_MODE='good'
rollback="$temporary/rollback"
mkdir "$rollback"
printf 'previous executable' > "$rollback/ssjack"
before="$(hash_file "$rollback/ssjack")"
export SSJACK_INSTALL_TEST_FAIL_INSTALLED=1
if install "$rollback"; then printf 'Expected installed-path probe failure.\n' >&2; exit 1; fi
unset SSJACK_INSTALL_TEST_FAIL_INSTALLED
[[ "$(hash_file "$rollback/ssjack")" == "$before" ]]
[[ "$(find "$rollback" -name 'ssjack.failed-*' | wc -l | tr -d ' ')" == 1 ]]

latest="$temporary/latest"
sh "$root/install.sh" --install-dir "$latest"
[[ "$(hash_file "$latest/ssjack")" == "$(hash_file "$fixture")" ]]

before="$(wc -l < "$SSJACK_CURL_CALLS")"
saved_arch="$SSJACK_FAKE_ARCH"
export SSJACK_FAKE_ARCH='unsupported-test-cpu'
if install "$temporary/unsupported"; then printf 'Unsupported CPU accepted.\n' >&2; exit 1; fi
export SSJACK_FAKE_ARCH="$saved_arch"
[[ "$(wc -l < "$SSJACK_CURL_CALLS")" == "$before" ]]

if sh "$root/install.sh" --version v0.0.0-test --install-dir relative; then printf 'Relative installation path accepted.\n' >&2; exit 1; fi
printf 'Installer tests passed without live downloads or global installation.\n'
