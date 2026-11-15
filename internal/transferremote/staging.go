package transferremote

import (
	"context"
	"fmt"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// createStagingTemplate creates a no-clobber staging directory with private
// mode 0700: a missing or symlinked parent is refused (exit 21), an existing
// path is refused (exit 22).
const createStagingTemplate = `set -eu
parent=%s
name=%s
path="$parent/$name"
if [ ! -d "$parent" ] || [ -L "$parent" ]; then
	exit 21
fi
if [ -e "$path" ] || [ -L "$path" ]; then
	exit 22
fi
if mkdir -m 700 "$path" 2>/dev/null; then
	exit 0
fi
if [ -e "$path" ] || [ -L "$path" ]; then
	exit 22
fi
exit 24
`

// cleanupStagingTemplate removes only a staging directory this job created:
// the remote side re-checks the name pattern and only removes directories;
// an absent path is success (idempotent); a non-directory at the path is
// refused (exit 21).
const cleanupStagingTemplate = `set -eu
parent=%s
name=%s
path="$parent/$name"
case "$name" in
	.ssjack-transfer-*) ;;
	*) exit 21 ;;
esac
if [ ! -e "$path" ] && [ ! -L "$path" ]; then
	exit 0
fi
if [ ! -d "$path" ] || [ -L "$path" ]; then
	exit 21
fi
rm -rf "$path" || exit 24
`

// CreateStaging creates a unique private staging directory in parent and
// returns its full path.
func (r *remoteRunner) CreateStaging(ctx context.Context, parent string) (string, error) {
	if err := r.ready(); err != nil {
		return "", err
	}
	if err := checkRemotePath(parent, r.limits); err != nil {
		return "", err
	}
	name, err := newStagingName()
	if err != nil {
		return "", err
	}
	command := fmt.Sprintf(createStagingTemplate, shellQuote(parent), shellQuote(name))
	if err := r.execute(ctx, command, nil, io.Discard); err != nil {
		return "", err
	}
	path := parent + "/" + name
	r.mu.Lock()
	r.created[path] = struct{}{}
	r.mu.Unlock()
	return path, nil
}

// CleanupStaging removes a staging directory this job created. Names that do
// not match the staging pattern and paths this job did not create are refused
// before any command runs.
func (r *remoteRunner) CleanupStaging(ctx context.Context, parent, name string) error {
	if err := r.ready(); err != nil {
		return err
	}
	if !validStagingName(name) {
		return classed(transfercore.ClassRefusedPath, msgRefused, -1)
	}
	if err := checkRemotePath(parent, r.limits); err != nil {
		return err
	}
	path := parent + "/" + name
	r.mu.Lock()
	_, ok := r.created[path]
	r.mu.Unlock()
	if !ok {
		return classed(transfercore.ClassRefusedPath, msgNotJobOwned, -1)
	}
	command := fmt.Sprintf(cleanupStagingTemplate, shellQuote(parent), shellQuote(name))
	return r.execute(ctx, command, nil, io.Discard)
}
