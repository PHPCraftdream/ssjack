package fileops

import (
	"context"
	"fmt"
	"io"
	"path"

	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

// PublishFileTemplate publishes a file without overwrite: hard-link staging
// to the destination (atomic, fails if it exists), then unlink staging. If
// linking is unsupported, fall back to an existence check plus mv -T,
// documented as racy.
const PublishFileTemplate = `set -eu
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

// PublishFileOverwriteTemplate publishes a file with overwrite: the
// destination must be a regular file; a symlink or directory is refused.
const PublishFileOverwriteTemplate = `set -eu
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

// PublishDirTemplate publishes a directory without overwrite: refuse an
// existing destination, then mv -T.
const PublishDirTemplate = `set -eu
src=%s
dst=%s
# The staging root is private until now; give the published tree the mode
# its subdirectories get from tar (0755 under the remote umask).
chmod "$(printf '%%o' "$((0755 & ~$(umask)))")" "$src" || exit 24
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

// PublishDirOverwriteTemplate publishes a directory with overwrite. An
// absent destination publishes directly (with a race re-check); an existing
// directory is renamed aside, the new one moved in and the old removed; a
// symlink or non-directory destination is refused (exit 21). Exit 24 covers
// a restored failure; exit 25 means publication failed and the restore also
// failed.
const PublishDirOverwriteTemplate = `set -eu
src=%s
dst=%s
old=%s
# The staging root is private until now; give the published tree the mode
# its subdirectories get from tar (0755 under the remote umask).
chmod "$(printf '%%o' "$((0755 & ~$(umask)))")" "$src" || exit 24
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
func (r *FileOps) PublishFile(ctx context.Context, staging, dest string, overwrite bool) error {
	if err := r.Ready(); err != nil {
		return err
	}
	if err := core.CheckRemotePath(staging, r.Limits); err != nil {
		return err
	}
	if err := core.CheckRemotePath(dest, r.Limits); err != nil {
		return err
	}
	template := core.PublicationTemplate(PublishFileTemplate, r.Capabilities())
	if overwrite {
		template = core.PublicationTemplate(PublishFileOverwriteTemplate, r.Capabilities())
	}
	command := fmt.Sprintf(template, core.ShellQuote(staging), core.ShellQuote(dest))
	return r.Execute(ctx, command, nil, io.Discard)
}

// PublishDir publishes a staged directory at dest. Without overwrite an
// existing destination is refused (exit 22). With overwrite it publishes
// when the destination is absent (like no-overwrite), replaces an existing
// directory, and refuses symlinks and non-directories (exit 21); the old directory is renamed
// aside, the new one moved in and the old removed, with restore on second
// rename failure (exit 24 restored, exit 25 restore failed too; both map to
// remote_failed, the exit code is still reported).
func (r *FileOps) PublishDir(ctx context.Context, staging, dest string, overwrite bool) error {
	if err := r.Ready(); err != nil {
		return err
	}
	if err := core.CheckRemotePath(staging, r.Limits); err != nil {
		return err
	}
	if err := core.CheckRemotePath(dest, r.Limits); err != nil {
		return err
	}
	if overwrite {
		aside, err := core.NewStagingName()
		if err != nil {
			return err
		}
		old := path.Dir(dest) + "/" + aside
		r.MarkCreated(old)
		command := fmt.Sprintf(core.PublicationTemplate(PublishDirOverwriteTemplate, r.Capabilities()), core.ShellQuote(staging), core.ShellQuote(dest), core.ShellQuote(old))
		return r.Execute(ctx, command, nil, io.Discard)
	}
	command := fmt.Sprintf(core.PublicationTemplate(PublishDirTemplate, r.Capabilities()), core.ShellQuote(staging), core.ShellQuote(dest))
	return r.Execute(ctx, command, nil, io.Discard)
}
