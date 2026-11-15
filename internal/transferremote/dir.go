package transferremote

import (
	"context"
	"fmt"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// treeCheckTemplate verifies the root is a directory, not a symlink, and
// contains no entry of any other type than regular file or directory
// (symlinks, devices, FIFOs, sockets).
const treeCheckTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit %d
fi
if find "$root" ! -type f ! -type d -print | IFS= read -r x; then
	exit %d
fi
`

const treeDirsTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit %d
fi
find "$root" -type d -print0
`

const treeFilesTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit %d
fi
find "$root" -type f -print0 | xargs -0 sha256sum
`

const treeSizesTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit %d
fi
find "$root" -type f -print0 | xargs -0 -n 1 wc -c
`

// PreflightTree rejects symlinks, devices, FIFOs and sockets (the
// non-regular probe), names with control characters or newlines (refused by
// the parser via ValidateRelPath) and over-limit trees. It returns the
// sorted manifest with sizes and hashes attached.
func (r *remoteRunner) PreflightTree(ctx context.Context, root string) (transfercore.Manifest, error) {
	if err := r.ready(); err != nil {
		return transfercore.Manifest{}, err
	}
	if err := checkRemotePath(root, r.limits); err != nil {
		return transfercore.Manifest{}, err
	}
	bound := listingBound(r.limits)
	check := fmt.Sprintf(treeCheckTemplate, shellQuote(root), exitRefusedPath, exitRefusedPath)
	if _, err := r.runListed(ctx, check, 1024); err != nil {
		return transfercore.Manifest{}, err
	}
	dirsData, err := r.runListed(ctx, fmt.Sprintf(treeDirsTemplate, shellQuote(root), exitRefusedPath), bound)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	filesData, err := r.runListed(ctx, fmt.Sprintf(treeFilesTemplate, shellQuote(root), exitRefusedPath), bound)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	sizesData, err := r.runListed(ctx, fmt.Sprintf(treeSizesTemplate, shellQuote(root), exitRefusedPath), bound)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	bad := transfercore.ClassRefusedPath
	dirs, err := parseDirListing(dirsData, root, r.limits, bad)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	files, err := parseFileListing(filesData, root, r.limits, bad)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	sizes, err := parseSizeListing(sizesData, root, r.limits, bad)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	for i := range files {
		size, ok := sizes[files[i].Path]
		if !ok {
			return transfercore.Manifest{}, listingError(transfercore.ClassRefusedPath, msgSizeMissing)
		}
		files[i].Size = size
		delete(sizes, files[i].Path)
	}
	if len(sizes) > 0 {
		return transfercore.Manifest{}, listingError(transfercore.ClassRefusedPath, msgSizeUnknown)
	}
	m := transfercore.Manifest{Dirs: dirs, Files: files}
	m.Normalize()
	if err := m.CheckLimits(r.limits); err != nil {
		return transfercore.Manifest{}, err
	}
	return m, nil
}

// VerifyTree compares the remote tree against a manifest. Sizes are ignored
// here: the sha256sum listing carries no sizes; verification is by hash,
// file count and directory count, per the design.
func (r *remoteRunner) VerifyTree(ctx context.Context, root string, manifest transfercore.Manifest) error {
	if err := r.ready(); err != nil {
		return err
	}
	if err := checkRemotePath(root, r.limits); err != nil {
		return err
	}
	expected := transfercore.Manifest{
		Dirs:  append([]string(nil), manifest.Dirs...),
		Files: append([]transfercore.Entry(nil), manifest.Files...),
	}
	expected.Normalize()
	check := fmt.Sprintf(treeCheckTemplate, shellQuote(root), exitIntegrity, exitIntegrity)
	if _, err := r.runListed(ctx, check, 1024); err != nil {
		return err
	}
	bound := listingBound(r.limits)
	dirsData, err := r.runListed(ctx, fmt.Sprintf(treeDirsTemplate, shellQuote(root), exitIntegrity), bound)
	if err != nil {
		return err
	}
	filesData, err := r.runListed(ctx, fmt.Sprintf(treeFilesTemplate, shellQuote(root), exitIntegrity), bound)
	if err != nil {
		return err
	}
	bad := transfercore.ClassIntegrity
	dirs, err := parseDirListing(dirsData, root, r.limits, bad)
	if err != nil {
		return err
	}
	files, err := parseFileListing(filesData, root, r.limits, bad)
	if err != nil {
		return err
	}
	expectedDirs := make(map[string]struct{}, len(expected.Dirs))
	for _, dir := range expected.Dirs {
		expectedDirs[dir] = struct{}{}
	}
	if len(dirs) != len(expected.Dirs) {
		return classed(transfercore.ClassIntegrity, msgIntegrity, -1)
	}
	for _, dir := range dirs {
		if _, ok := expectedDirs[dir]; !ok {
			return classed(transfercore.ClassIntegrity, msgIntegrity, -1)
		}
	}
	if len(files) != len(expected.Files) {
		return classed(transfercore.ClassIntegrity, msgIntegrity, -1)
	}
	expectedFiles := make(map[string][32]byte, len(expected.Files))
	for _, file := range expected.Files {
		expectedFiles[file.Path] = file.SHA256
	}
	for _, file := range files {
		want, ok := expectedFiles[file.Path]
		if !ok || want != file.SHA256 {
			return classed(transfercore.ClassIntegrity, msgIntegrity, -1)
		}
	}
	return nil
}

// tarOutTemplate streams the tree contents ('.') as a tar archive; entries
// have relative ./ names.
const tarOutTemplate = `set -eu
root=%s
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit 21
fi
cd "$root" || exit 21
tar -c -f - . || exit 24
`

// tarInTemplate extracts a tar stream with --no-same-owner
// --no-same-permissions so ownership and special bits are not restored.
const tarInTemplate = `set -eu
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
func (r *remoteRunner) TarOut(ctx context.Context, root string, dst io.Writer) error {
	if err := r.ready(); err != nil {
		return err
	}
	if err := checkRemotePath(root, r.limits); err != nil {
		return err
	}
	return r.execute(ctx, fmt.Sprintf(tarOutTemplate, shellQuote(root)), nil, dst)
}

// TarIn extracts a tar stream into root with --no-same-owner
// --no-same-permissions so ownership and special bits are not restored.
func (r *remoteRunner) TarIn(ctx context.Context, root string, src io.Reader) error {
	if err := r.ready(); err != nil {
		return err
	}
	if err := checkRemotePath(root, r.limits); err != nil {
		return err
	}
	return r.execute(ctx, fmt.Sprintf(tarInTemplate, shellQuote(root)), src, io.Discard)
}
