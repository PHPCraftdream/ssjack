#!/bin/sh
set -eu

usage() {
    printf '%s\n' 'Usage: sh build.sh [--install-dir ABSOLUTE_DIRECTORY]'
    printf '%s\n' 'Build this checkout for native Linux/macOS and install globally (default /usr/local/bin).'
    printf '%s\n' 'Requires Git and the Go toolchain required by go.mod. Never elevates or migrates credentials.'
}

fail() { printf '%s\n' "$1" >&2; exit 1; }
install_dir='/usr/local/bin'
while [ "$#" -gt 0 ]; do
    case "$1" in
        --install-dir)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail 'Missing installation directory.'
            install_dir=$2
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; fail 'Unknown build option.' ;;
    esac
done
case "$install_dir" in /*) ;; *) fail 'The installation directory must be absolute.' ;; esac
case "$(uname -s)" in
    Linux) os='linux' ;;
    Darwin) os='darwin' ;;
    *) fail 'Unsupported OS. On Windows use build.ps1.' ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch='amd64' ;;
    aarch64|arm64) arch='arm64' ;;
    *) fail 'Unsupported CPU architecture; expected amd64 or arm64.' ;;
esac
command -v git >/dev/null 2>&1 || fail 'Git is required to identify the source revision.'
command -v go >/dev/null 2>&1 || fail 'Install the Go toolchain required by go.mod first.'
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
[ -f "$root/go.mod" ] && [ -f "$root/install.sh" ] || fail 'Run the script from a complete ssjack source checkout.'
revision=$(git -C "$root" rev-parse --verify HEAD) || fail 'Cannot identify the checkout commit.'
printf '%s\n' "$revision" | grep -Eq '^[0-9a-f]{40}$' || fail 'Invalid checkout commit.'
changes=$(git -C "$root" status --porcelain --untracked-files=normal) || fail 'Cannot inspect source status.'
if [ -n "$changes" ]; then revision="$revision-dirty"; fi

temp_root=${TMPDIR:-/tmp}
case "$temp_root" in /*) ;; *) fail 'TMPDIR must be an absolute directory.' ;; esac
stage=$(mktemp -d "$temp_root/ssjack-source-build.XXXXXXXX")
cleanup() {
    code=$?
    trap - EXIT HUP INT TERM
    rm -f "$stage/ssjack" || code=1
    rmdir "$stage" || code=1
    exit "$code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'Building ssjack for %s/%s from %s\n' "$os" "$arch" "$revision"
(
    cd "$root"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off GOFLAGS='' \
        go build -mod=readonly -trimpath -buildvcs=true \
        -ldflags "-X github.com/PHPCraftdream/ssjack/internal/buildinfo.Commit=$revision" \
        -o "$stage/ssjack" ./cmd/ssjack
) || fail 'Build failed; installation was not started.'
if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$stage/ssjack")
elif command -v shasum >/dev/null 2>&1; then
    digest=$(shasum -a 256 "$stage/ssjack")
else
    fail 'sha256sum or shasum is required; installation was not started.'
fi
digest=${digest%% *}
printf '%s\n' "$digest" | grep -Eq '^[0-9a-fA-F]{64}$' || fail 'Invalid build checksum.'
sh "$root/install.sh" --candidate "$stage/ssjack" --sha256 "$digest" --install-dir "$install_dir"
printf 'Built and installed checkout %s. No process was stopped; no database was changed.\n' "$revision"
