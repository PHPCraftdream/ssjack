// Package fileops holds the single-file remote operations: staging directory
// creation and cleanup, file write, stat and read, and atomic publication.
package fileops

import (
	"context"
	"fmt"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

// writeFileTemplate creates the file via `cat >` with mode 0666 minus the
// remote umask; with the execute bit `chmod +x` adds the x bits. The file
// lives in the 0700 staging directory until publication; no ownership or
// special bits are ever set.
const writeFileTemplate = `set -eu
path=%s
if [ -e "$path" ] || [ -L "$path" ]; then
	exit 22
fi
cat > "$path" || exit 24
`

// writeFileExecSuffix is appended to writeFileTemplate when executable.
const writeFileExecSuffix = "\nchmod +x \"$path\" || exit 24\n"

// WriteFile streams src into a fresh file at path and returns the byte count.
func (r *FileOps) WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error) {
	if err := r.Ready(); err != nil {
		return 0, err
	}
	if err := core.CheckRemotePath(path, r.Limits); err != nil {
		return 0, err
	}
	command := fmt.Sprintf(writeFileTemplate, core.ShellQuote(path))
	if executable {
		command += writeFileExecSuffix
	}
	cr := core.NewCountingReader(src)
	err := r.Execute(ctx, command, cr, io.Discard)
	return cr.Count(), err
}

// StatFileTemplate reports size and SHA-256 of a regular file.
const StatFileTemplate = `set -eu
path=%s
if [ -L "$path" ] || [ ! -f "$path" ]; then
	exit 21
fi
wc -c < "$path"
%s
`

// StatFile returns the size and SHA-256 of a remote regular file. Symlinks
// and non-regular files are refused (exit 21).
func (r *FileOps) StatFile(ctx context.Context, path string) (int64, [32]byte, error) {
	if err := r.Ready(); err != nil {
		return 0, [32]byte{}, err
	}
	if err := core.CheckRemotePath(path, r.Limits); err != nil {
		return 0, [32]byte{}, err
	}
	data, err := r.RunListed(ctx, fmt.Sprintf(StatFileTemplate, core.ShellQuote(path), core.StatHashCommand(r.Capabilities().Hash)), 8192)
	if err != nil {
		return 0, [32]byte{}, err
	}
	return core.ParseStatOutput(data, path)
}

// readFileTemplate streams a regular file; symlinks and non-regular files are
// refused (exit 21 -> ClassRefusedPath).
const readFileTemplate = `set -eu
path=%s
if [ -L "$path" ] || [ ! -f "$path" ]; then
	exit 21
fi
cat "$path" || exit 24
`

// ReadFile streams a remote regular file into dst and returns the byte count.
func (r *FileOps) ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error) {
	if err := r.Ready(); err != nil {
		return 0, err
	}
	if err := core.CheckRemotePath(path, r.Limits); err != nil {
		return 0, err
	}
	cw := core.NewCountingWriter(dst)
	err := r.Execute(ctx, fmt.Sprintf(readFileTemplate, core.ShellQuote(path)), nil, cw)
	return cw.Count(), err
}

// FileOps runs the single-file operations of a remote target.
type FileOps struct{ *core.Runner }

// New returns the FileOps of a runner.
func New(r *core.Runner) *FileOps { return &FileOps{r} }
