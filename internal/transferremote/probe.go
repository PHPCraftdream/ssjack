package transferremote

import (
	"context"
	"fmt"
	"io"
)

// probeTemplate verifies the remote requirements: POSIX sh and the tools
// cat, sha256sum, find, xargs -0, tar, rm, mv, wc. sh itself is proven by the
// command already running; wc is POSIX-mandatory and needed for sizes. The
// mv -T support is tested functionally in a private directory under
// ${TMPDIR:-/tmp} that is removed afterwards.
const probeTemplate = `set -eu
for tool in cat sha256sum find xargs tar rm mv wc; do
	command -v "$tool" >/dev/null || exit 20
done
if ! (: | xargs -0 sha256sum >/dev/null); then
	exit 20
fi
d="${TMPDIR:-/tmp}"%s
if ! mkdir -m 700 "$d"; then
	exit 20
fi
if ! (: > "$d/probe" && mv -T "$d/probe" "$d/probe.moved"); then
	rm -rf "$d" || :
	exit 20
fi
rm -rf "$d" || exit 20
`

// Probe checks that the remote target has every tool the transfer needs.
func (r *remoteRunner) Probe(ctx context.Context) error {
	if err := r.ready(); err != nil {
		return err
	}
	suffix, err := newRandomSuffix()
	if err != nil {
		return err
	}
	command := fmt.Sprintf(probeTemplate, shellQuote("/"+probePrefix+suffix))
	return r.execute(ctx, command, nil, io.Discard)
}
