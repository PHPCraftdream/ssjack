package transferengine

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// Source kind detection. The kind always comes from the source, never from
// the caller. Locally, a source that opens as a regular file is a file and a
// source that only walks as a tree is a directory (Upload dispatches on
// exactly that). Remotely, a path that stats as a regular file is a file and
// a path that only preflights as a tree is a directory.

// remoteSourceKind stats the remote path as a file; when that is refused it
// probes the path as a tree, so a directory source is distinguished from any
// other refusal. size and sum are the file preflight values; manifest is the
// tree preflight of a directory source. When both probes are refused the
// StatFile error is returned.
func remoteSourceKind(ctx context.Context, remote transferremote.Remote, p string) (Kind, int64, [32]byte, transfercore.Manifest, error) {
	size, sum, err := remote.StatFile(ctx, p)
	if err == nil {
		return KindFile, size, sum, transfercore.Manifest{}, nil
	}
	manifest, treeErr := remote.PreflightTree(ctx, p)
	if treeErr == nil {
		return KindDir, 0, [32]byte{}, manifest, nil
	}
	if transfercore.ClassOf(treeErr) == transfercore.ClassLimit {
		return KindFile, 0, [32]byte{}, transfercore.Manifest{}, treeErr
	}
	return KindFile, 0, [32]byte{}, transfercore.Manifest{}, err
}
