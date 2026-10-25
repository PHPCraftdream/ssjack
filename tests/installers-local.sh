#!/usr/bin/env bash
set -euo pipefail
root="${1:?source root}"
fixture="${2:?fixture binary}"
temporary="${3:?temporary directory}"
export SSJACK_EFFECTIVE_UID=0
export SSJACK_BACKUP_STATE=unused
cat > "$temporary/tools/lsof" <<'MOCK'
#!/bin/sh
case "$SSJACK_BACKUP_STATE" in
    busy) printf '12345\n'; exit 0 ;;
    unknown) printf 'inspection denied\n' >&2; exit 1 ;;
    unused) exit 1 ;;
    *) exit 2 ;;
esac
MOCK
chmod +x "$temporary/tools/lsof"

hash_file() {
    local value
    if command -v sha256sum >/dev/null 2>&1; then value="$(sha256sum "$1")"; else value="$(shasum -a 256 "$1")"; fi
    printf '%s\n' "${value%% *}"
}

local_install="$temporary/local-candidate"
requests_before_local="$(wc -l < "$SSJACK_CURL_CALLS")"
sh "$root/install.sh" --candidate "$fixture" --sha256 "$(hash_file "$fixture")" --install-dir "$local_install"
[[ "$(hash_file "$local_install/ssjack")" == "$(hash_file "$fixture")" ]]
[[ "$(wc -l < "$SSJACK_CURL_CALLS")" == "$requests_before_local" ]]
rm -f "$SSJACK_INSTALL_TEST_MARKER"
if sh "$root/install.sh" --candidate "$fixture" --sha256 "$(printf '%064d' 0)" --install-dir "$temporary/bad-local"; then
    printf 'Bad local candidate checksum accepted.\n' >&2; exit 1
fi
[[ ! -e "$SSJACK_INSTALL_TEST_MARKER" ]]

for state in busy unknown; do
    held="$local_install/ssjack.previous-20260101T010203Z-1234abcd"
    printf 'previous fixture' > "$held"
    export SSJACK_BACKUP_STATE="$state"
    sh "$root/install.sh" --candidate "$fixture" --sha256 "$(hash_file "$fixture")" --install-dir "$local_install"
    [[ -f "$held" ]]
    export SSJACK_BACKUP_STATE=unused
    sh "$root/install.sh" --candidate "$fixture" --sha256 "$(hash_file "$fixture")" --install-dir "$local_install"
    [[ ! -e "$held" ]]
done
held="$local_install/ssjack.previous-20260101T010203Z-1234abcd"
printf 'previous fixture' > "$held"
export SSJACK_EFFECTIVE_UID=1000
sh "$root/install.sh" --candidate "$fixture" --sha256 "$(hash_file "$fixture")" --install-dir "$local_install"
[[ -f "$held" ]]
export SSJACK_EFFECTIVE_UID=0
foreign="$local_install/ssjack.previous-user-owned"
printf 'foreign fixture' > "$foreign"
sh "$root/install.sh" --candidate "$fixture" --sha256 "$(hash_file "$fixture")" --install-dir "$local_install"
[[ ! -e "$held" && -f "$foreign" ]]

linked="$local_install/ssjack.previous-20260101T010203Z-1234abcd"
ln -s "$foreign" "$linked"
sh "$root/install.sh" --candidate "$fixture" --sha256 "$(hash_file "$fixture")" --install-dir "$local_install"
[[ -L "$linked" && -f "$foreign" ]]
ln -s "$fixture" "$temporary/linked-candidate"
if sh "$root/install.sh" --candidate "$temporary/linked-candidate" --sha256 "$(hash_file "$fixture")" --install-dir "$temporary/linked-install"; then
    printf 'Linked local candidate accepted.\n' >&2; exit 1
fi
printf 'Local candidate and conservative backup cleanup tests passed.\n'
