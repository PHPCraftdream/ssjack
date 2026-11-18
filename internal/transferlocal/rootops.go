package transferlocal

import (
	"io"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/chunk"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/source"
)

// WalkSource walks the tree at rel under the root and returns the manifest of
// regular files and directories only. rel "" means the root itself; a regular
// file rel yields a single-file manifest whose Path is rel itself.
func (r *Root) WalkSource(rel string, limits transfercore.Limits) (transfercore.Manifest, error) {
	return source.Walk(r.path, rel, limits)
}

// OpenSourceFile no-follow opens rel as a regular file for single-file
// transfers.
func (r *Root) OpenSourceFile(rel string) (*os.File, int64, error) {
	return source.OpenFile(r.path, rel)
}

// BuildTar writes a deterministic tar of the manifest tree under rel to w,
// re-verifying every file's size and SHA-256 while streaming.
func (r *Root) BuildTar(w io.Writer, rel string, manifest transfercore.Manifest) error {
	return source.BuildTar(r.path, w, rel, manifest)
}

// OpenChunkStaging looks at the keyed staging directory of the download of
// destRel: it adopts an existing one, and creates it when create is set. See
// package chunk for the adoption rules.
func (r *Root) OpenChunkStaging(destRel, key string, source [32]byte, overwrite, create bool) (*ChunkStaging, ChunkState, error) {
	return chunk.Open(r.path, destRel, key, source, overwrite, create)
}

// CollectStaleChunkStaging removes at most ChunkGCLimit idle keyed staging
// directories next to destRel, never the one of excludeKey, and returns how
// many were removed.
func (r *Root) CollectStaleChunkStaging(destRel, excludeKey string) int {
	return chunk.CollectStale(r.path, destRel, excludeKey)
}
