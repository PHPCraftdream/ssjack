// Package tree holds the remote directory-tree operations: preflight and
// verification by listing, tar streaming in and out, and the strict listing
// and manifest parsers.
package tree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

// TreeCheckTemplate verifies the root is a directory, not a symlink, and
// contains no entry of any other type than regular file or directory
// (symlinks, devices, FIFOs, sockets).
const TreeCheckTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit %d
fi
if find "$root" ! -type f ! -type d -print | IFS= read -r x; then
	exit %d
fi
`

const TreeDirsTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit %d
fi
find "$root" -type d -print0
`

const TreeFilesTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit %d
fi
find "$root" -type f -print0 | %s
`

// TreeHashTail returns the xargs pipeline tail that prints one GNU
// sha256sum line per file for the probed hash variant. Tool-specific filename
// formatting is avoided for portable hash variants by printing the original
// find path from the shell argument.
func TreeHashTail(hash string) string {
	switch hash {
	case core.HashShasum:
		return `xargs -0 -n 1 sh -c '[ "$#" -gt 0 ] || exit 0; f="$1"; out=$(shasum -a 256 < "$f") || exit 24; hash=${out%% *}; [ "$out" = "$hash  -" ] || exit 24; printf "%s  %s\n" "$hash" "$f"' _`
	case core.HashSha256q:
		return `xargs -0 -n 1 sh -c '[ "$#" -gt 0 ] || exit 0; f="$1"; hash=$(sha256 -q "$f") || exit 24; printf "%s  %s\n" "$hash" "$f"' _`
	default:
		return `xargs -0 sha256sum`
	}
}

const TreeSizesTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit %d
fi
find "$root" -type f -print0 | xargs -0 -n 1 wc -c
`

const TreePortableSizesTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit %d
fi
find "$root" -type f -print0 | xargs -0 -n 1 sh -c '[ "$#" -gt 0 ] || exit 0; f="$1"; size=$(wc -c < "$f") || exit 24; printf "%%s %%s\n" "$size" "$f"' _
`

// PreflightTree rejects symlinks, devices, FIFOs and sockets (the
// non-regular probe), names with control characters or newlines (refused by
// the parser via ValidateRelPath) and over-limit trees. It returns the
// sorted manifest with sizes and hashes attached.
func (r *TreeOps) PreflightTree(ctx context.Context, root string) (transfercore.Manifest, error) {
	if err := r.Ready(); err != nil {
		return transfercore.Manifest{}, err
	}
	if err := core.CheckRemotePath(root, r.Limits); err != nil {
		return transfercore.Manifest{}, err
	}
	bound := listingBound(r.Limits)
	check := fmt.Sprintf(TreeCheckTemplate, core.ShellQuote(root), core.ExitRefusedPath, core.ExitRefusedPath)
	if _, err := r.RunListed(ctx, check, 1024); err != nil {
		return transfercore.Manifest{}, err
	}
	dirsData, err := r.RunListed(ctx, fmt.Sprintf(TreeDirsTemplate, core.ShellQuote(root), core.ExitRefusedPath), bound)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	filesData, err := r.RunListed(ctx, fmt.Sprintf(TreeFilesTemplate, core.ShellQuote(root), core.ExitRefusedPath, TreeHashTail(r.Capabilities().Hash)), bound)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	sizesTemplate := TreeSizesTemplate
	if !r.Capabilities().WcNames {
		sizesTemplate = TreePortableSizesTemplate
	}
	sizesData, err := r.RunListed(ctx, fmt.Sprintf(sizesTemplate, core.ShellQuote(root), core.ExitRefusedPath), bound)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	bad := transfercore.ClassRefusedPath
	dirs, err := parseDirListing(dirsData, root, r.Limits, bad)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	files, err := parseFileListing(filesData, root, r.Limits, bad)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	sizes, err := parseSizeListing(sizesData, root, r.Limits, bad)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	for i := range files {
		size, ok := sizes[files[i].Path]
		if !ok {
			return transfercore.Manifest{}, core.ListingError(transfercore.ClassRefusedPath, msgSizeMissing)
		}
		files[i].Size = size
		delete(sizes, files[i].Path)
	}
	if len(sizes) > 0 {
		return transfercore.Manifest{}, core.ListingError(transfercore.ClassRefusedPath, msgSizeUnknown)
	}
	m := transfercore.Manifest{Dirs: dirs, Files: files}
	m.Normalize()
	if err := m.CheckLimits(r.Limits); err != nil {
		return transfercore.Manifest{}, err
	}
	return m, nil
}

// VerifyTree compares the remote tree against a manifest. Sizes are ignored
// here: the sha256sum listing carries no sizes; verification is by hash,
// file count and directory count, per the design.
func (r *TreeOps) VerifyTree(ctx context.Context, root string, manifest transfercore.Manifest) error {
	if err := r.Ready(); err != nil {
		return err
	}
	if err := core.CheckRemotePath(root, r.Limits); err != nil {
		return err
	}
	expected := transfercore.Manifest{
		Dirs:  append([]string(nil), manifest.Dirs...),
		Files: append([]transfercore.Entry(nil), manifest.Files...),
	}
	expected.Normalize()
	check := fmt.Sprintf(TreeCheckTemplate, core.ShellQuote(root), core.ExitIntegrity, core.ExitIntegrity)
	if _, err := r.RunListed(ctx, check, 1024); err != nil {
		return err
	}
	bound := listingBound(r.Limits)
	dirsData, err := r.RunListed(ctx, fmt.Sprintf(TreeDirsTemplate, core.ShellQuote(root), core.ExitIntegrity), bound)
	if err != nil {
		return err
	}
	filesData, err := r.RunListed(ctx, fmt.Sprintf(TreeFilesTemplate, core.ShellQuote(root), core.ExitIntegrity, TreeHashTail(r.Capabilities().Hash)), bound)
	if err != nil {
		return err
	}
	bad := transfercore.ClassIntegrity
	dirs, err := parseDirListing(dirsData, root, r.Limits, bad)
	if err != nil {
		return err
	}
	files, err := parseFileListing(filesData, root, r.Limits, bad)
	if err != nil {
		return err
	}
	expectedDirs := make(map[string]struct{}, len(expected.Dirs))
	for _, dir := range expected.Dirs {
		expectedDirs[dir] = struct{}{}
	}
	if len(dirs) != len(expected.Dirs) {
		return core.Classed(transfercore.ClassIntegrity, core.MsgIntegrity, -1)
	}
	for _, dir := range dirs {
		if _, ok := expectedDirs[dir]; !ok {
			return core.Classed(transfercore.ClassIntegrity, core.MsgIntegrity, -1)
		}
	}
	if len(files) != len(expected.Files) {
		return core.Classed(transfercore.ClassIntegrity, core.MsgIntegrity, -1)
	}
	expectedFiles := make(map[string][32]byte, len(expected.Files))
	for _, file := range expected.Files {
		expectedFiles[file.Path] = file.SHA256
	}
	for _, file := range files {
		want, ok := expectedFiles[file.Path]
		if !ok || want != file.SHA256 {
			return core.Classed(transfercore.ClassIntegrity, core.MsgIntegrity, -1)
		}
	}
	return nil
}

// TarOutTemplate streams the tree contents ('.') as a tar archive; entries
// have relative ./ names.
const TarOutTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit 21
fi
cd "$root" || exit 21
tar -c -f - . || exit 24
`

// TarInTemplate extracts a tar stream with --no-same-owner
// --no-same-permissions so ownership and special bits are not restored.
const TarInTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit 21
fi
cd "$root" || exit 21
tar -x --no-same-owner --no-same-permissions -f - || exit 24
`

// TarOut streams the tree contents ('.') as a tar archive to dst; entries
// are relative ./ names; ownership and special bits are not preserved by
// this side.
func (r *TreeOps) TarOut(ctx context.Context, root string, dst io.Writer) error {
	if err := r.Ready(); err != nil {
		return err
	}
	if err := core.CheckRemotePath(root, r.Limits); err != nil {
		return err
	}
	return r.Execute(ctx, fmt.Sprintf(TarOutTemplate, core.ShellQuote(root)), nil, dst)
}

const TarInEmptyTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit 21
fi
`

// tarInSourceReadFailed is deliberately content-free: raw source errors must
// not escape through the stream runner or into a returned error.
var tarInSourceReadFailed = errors.New("tar input source read failed")

// tarInSource records source read failures without retaining or exposing their
// text. TarIn reads the prefix and the stream runner may consume the remainder
// concurrently, so the state is protected by a mutex.
type tarInSource struct {
	reader io.Reader
	mu     sync.Mutex
	failed bool
	eof    bool
}

func (s *tarInSource) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if err != nil {
		s.mu.Lock()
		if err == io.EOF {
			s.eof = true
		} else {
			s.failed = true
			err = tarInSourceReadFailed
		}
		s.mu.Unlock()
	}
	return n, err
}

func (s *tarInSource) state() (failed, eof bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed, s.eof
}

type tarInReplayError struct {
	err  error
	next io.Reader
}

func (r *tarInReplayError) Read(p []byte) (int, error) {
	if r.err != nil {
		err := r.err
		r.err = nil
		return 0, err
	}
	return r.next.Read(p)
}

// TarIn extracts a tar stream into root with --no-same-owner
// --no-same-permissions so ownership and special bits are not restored.
func (r *TreeOps) TarIn(ctx context.Context, root string, src io.Reader) error {
	if err := r.Ready(); err != nil {
		return err
	}
	if err := core.CheckRemotePath(root, r.Limits); err != nil {
		return err
	}

	if src == nil {
		return r.Execute(ctx, fmt.Sprintf(TarInTemplate, core.ShellQuote(root)), nil, io.Discard)
	}

	tracked := &tarInSource{reader: src}
	var prefix [1025]byte
	n, _ := io.ReadFull(tracked, prefix[:])
	failed, eof := tracked.state()
	if n == 1024 && eof && !failed {
		empty := true
		for _, b := range prefix[:n] {
			if b != 0 {
				empty = false
				break
			}
		}
		if empty {
			return r.Execute(ctx, fmt.Sprintf(TarInEmptyTemplate, core.ShellQuote(root)), nil, io.Discard)
		}
	}

	var replayErr error
	if failed {
		replayErr = tarInSourceReadFailed
	}
	stdin := io.MultiReader(bytes.NewReader(prefix[:n]), &tarInReplayError{err: replayErr, next: tracked})
	if err := r.Execute(ctx, fmt.Sprintf(TarInTemplate, core.ShellQuote(root)), stdin, io.Discard); err != nil {
		return err
	}
	failed, _ = tracked.state()
	if failed {
		if ctx.Err() != nil {
			return core.Classed(transfercore.ClassCancelled, core.MsgCancelled, -1)
		}
		return core.Classed(transfercore.ClassRemoteFailed, core.MsgRemoteFailed, -1)
	}
	return nil
}

// TreeOps runs the directory-tree operations of a remote target.
type TreeOps struct{ *core.Runner }

// New returns the TreeOps of a runner.
func New(r *core.Runner) *TreeOps { return &TreeOps{r} }
