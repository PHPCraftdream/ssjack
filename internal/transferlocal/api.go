package transferlocal

import (
	"io"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/chunk"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/hashcount"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/staging"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/tarin"
)

// The implementation lives in subpackages; these names are the public API.

// Staging is one job-owned staging directory inside the destination's parent.
type Staging = staging.Staging

// Kind selects what Staging.Publish puts at the destination.
type Kind = staging.Kind

// Publication kinds.
const (
	KindFile = staging.KindFile
	KindDir  = staging.KindDir
)

// NewStaging creates a private exclusive staging directory in dir; parents
// are never created implicitly.
func NewStaging(destRel string, dir string, overwrite bool) (*Staging, error) {
	return staging.NewStaging(destRel, dir, overwrite)
}

// ExtractTar reads a tar stream into the staging directory under the local
// safety rules and returns the normalized computed manifest.
func ExtractTar(r io.Reader, stg *Staging, want *transfercore.Manifest, limits transfercore.Limits) (transfercore.Manifest, error) {
	return tarin.ExtractTar(r, stg, want, limits)
}

// CopyLimited copies src into dst, returning the byte count and SHA-256 of
// what was read and written. A chunk that would exceed max is not written.
func CopyLimited(dst io.Writer, src io.Reader, max int64) (int64, [32]byte, error) {
	return hashcount.CopyLimited(dst, src, max)
}

// ChunkStaging is the keyed staging directory of one chunked download.
type ChunkStaging = chunk.ChunkStaging

// PartWriter writes one part of a chunked download.
type PartWriter = chunk.PartWriter

// ChunkState is the verdict of Root.OpenChunkStaging.
type ChunkState = chunk.ChunkState

// Chunk staging verdicts.
const (
	ChunkAbsent  = chunk.ChunkAbsent
	ChunkCreated = chunk.ChunkCreated
	ChunkReused  = chunk.ChunkReused
	ChunkForeign = chunk.ChunkForeign
)

// Chunk staging garbage collection bounds.
const (
	ChunkStaleAfter = chunk.ChunkStaleAfter
	ChunkGCLimit    = chunk.ChunkGCLimit
)

// Chunk staging errors.
var (
	ErrChunkPartInvalid = chunk.ErrChunkPartInvalid
	ErrChunkStagingGone = chunk.ErrChunkStagingGone
)
