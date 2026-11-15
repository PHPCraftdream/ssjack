package transferremote

import (
	"context"
	"fmt"
	"io"
	"path"
)

// publishFileTemplate publishes a file without overwrite: hard-link staging
// to the destination (atomic, fails if it exists), then unlink staging. If
// linking is unsupported, fall back to an existence check plus mv -T,
// documented as racy.
const publishFileTemplate = `set -eu
src=%s
dst=%s
if [ -L "$dst" ] || [ -e "$dst" ]; then
	exit 22
fi
if ln "$src" "$dst"; then
	rm -f "$src" || exit 24
	exit 0
fi
if [ -e "$dst" ] || [ -L "$dst" ]; then
	exit 22
fi
if mv -T "$src" "$dst"; then
	exit 0
fi
if [ -e "$dst" ] || [ -L "$dst" ]; then
	exit 22
fi
exit 24
`

// publishFileOverwriteTemplate publishes a file with overwrite: the
// destination must be a regular file; a symlink or directory is refused.
const publishFileOverwriteTemplate = `set -eu
src=%s
dst=%s
if [ -L "$dst" ] || [ -d "$dst" ]; then
	exit 21
fi
if [ -e "$dst" ] && [ ! -f "$dst" ]; then
	exit 21
fi
mv -T -f "$src" "$dst" || exit 24
`

// publishDirTemplate publishes a directory without overwrite: refuse an
// existing destination, then mv -T.
const publishDirTemplate = `set -eu
src=%s
dst=%s
if [ -L "$dst" ] || [ -e "$dst" ]; then
	exit 22
fi
if mv -T "$src" "$dst"; then
	exit 0
fi
if [ -e "$dst" ] || [ -L "$dst" ]; then
	exit 22
fi
exit 24
`

// publishDirOverwriteTemplate publishes a directory with overwrite. An
// absent destination publishes directly (with a race re-check); an existing
// directory is renamed aside, the new one moved in and the old removed; a
// symlink or non-directory destination is refused (exit 21). Exit 24 covers
// a restored failure; exit 25 means publication failed and the restore also
// failed.
const publishDirOverwriteTemplate = `set -eu
src=%s
dst=%s
old=%s
if [ -L "$dst" ]; then
	exit 21
fi
if [ -e "$dst" ] && [ ! -d "$dst" ]; then
	exit 21
fi
if [ ! -e "$dst" ]; then
	if mv -T "$src" "$dst"; then
		exit 0
	fi
	if [ -e "$dst" ] || [ -L "$dst" ]; then
		exit 22
	fi
	exit 24
fi
if [ -e "$old" ] || [ -L "$old" ]; then
	exit 22
fi
if ! mv -T "$dst" "$old"; then
	exit 24
fi
if mv -T "$src" "$dst"; then
	rm -rf "$old" || exit 24
	exit 0
fi
if mv -T "$old" "$dst"; then
	exit 24
fi
exit 25
`

// PublishFile publishes a staged file at dest. Without overwrite the
// publication is atomic via hard link (exit 22 if dest exists; exit 24
// covers the documented racy mv -T fallback). With overwrite the destination
// must be a regular file: symlinks and other types are refused (exit 21).
func (r *remoteRunner) PublishFile(ctx context.Context, staging, dest string, overwrite bool) error {
	if err := r.ready(); err != nil {
		return err
	}
	if err := checkRemotePath(staging, r.limits); err != nil {
		return err
	}
	if err := checkRemotePath(dest, r.limits); err != nil {
		return err
	}
	template := publishFileTemplate
	if overwrite {
		template = publishFileOverwriteTemplate
	}
	command := fmt.Sprintf(template, shellQuote(staging), shellQuote(dest))
	return r.execute(ctx, command, nil, io.Discard)
}

// PublishDir publishes a staged directory at dest. Without overwrite an
// existing destination is refused (exit 22). With overwrite it publishes
// when the destination is absent (like no-overwrite), replaces an existing
// directory, and refuses symlinks and non-directories (exit 21); the old directory is renamed
// aside, the new one moved in and the old removed, with restore on second
// rename failure (exit 24 restored, exit 25 restore failed too; both map to
// remote_failed, the exit code is still reported).
func (r *remoteRunner) PublishDir(ctx context.Context, staging, dest string, overwrite bool) error {
	if err := r.ready(); err != nil {
		return err
	}
	if err := checkRemotePath(staging, r.limits); err != nil {
		return err
	}
	if err := checkRemotePath(dest, r.limits); err != nil {
		return err
	}
	if overwrite {
		aside, err := newStagingName()
		if err != nil {
			return err
		}
		old := path.Dir(dest) + "/" + aside
		r.mu.Lock()
		r.created[old] = struct{}{}
		r.mu.Unlock()
		command := fmt.Sprintf(publishDirOverwriteTemplate, shellQuote(staging), shellQuote(dest), shellQuote(old))
		return r.execute(ctx, command, nil, io.Discard)
	}
	command := fmt.Sprintf(publishDirTemplate, shellQuote(staging), shellQuote(dest))
	return r.execute(ctx, command, nil, io.Discard)
}
