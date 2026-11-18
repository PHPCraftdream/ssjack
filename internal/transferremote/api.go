package transferremote

import (
	"context"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/chunk"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/tree"
)

// ChunkRemote is the remote command layer of the chunked resumable mode
// (docs/FILE-TRANSFER.md, "Chunked resumable mode"). Every method runs one
// fixed command template in a fresh session; nothing here decides strategy.
// Methods that touch a staging directory take the destination's parent and
// the staging key (see StagingKey); the directory name is derived from it.
//
// New returns a value that also implements ChunkRemote; NewChunk returns it
// directly. Chunked methods fail closed with ClassUnsupportedRemote when the
// probed capabilities lack what they need (see ChunkCaps).
type ChunkRemote interface {
	Remote

	// ChunkCaps returns the probed chunked-mode capabilities; before Probe it
	// is the GNU-compatible default.
	ChunkCaps() ChunkCaps

	// EnsureStaging creates the marked staging directory (mode 0700, no
	// clobber) or verifies an existing one. A foreign object yields
	// StagingForeign and is left untouched.
	EnsureStaging(ctx context.Context, parent, key string) (StagingState, error)
	// UploadPart stores exactly part.Len bytes read from src as
	// part-<off>-<len>. The part counts only when PartResult.Stored is true.
	UploadPart(ctx context.Context, parent, key string, part transferlink.Range, src io.Reader) (PartResult, error)
	// ListStaging lists the staging directory of a file of fileSize bytes and
	// builds the coverage; it removes stale temporary files remotely, among them
	// every leftover assembled.<rnd>.tmp (counted in StagingListing.StaleAssembled),
	// so the caller's disk preflight after the listing sees the space free.
	ListStaging(ctx context.Context, parent, key string, fileSize int64) (StagingListing, error)
	// RemoveStagingEntries removes ignored part entries named by a listing.
	RemoveStagingEntries(ctx context.Context, parent, key string, names []string) error
	// AssembleStaging concatenates the parts, which must tile [0, size)
	// exactly, into a random-named file in the staging directory and returns
	// its path, size and SHA-256 computed with the selected hash command.
	AssembleStaging(ctx context.Context, parent, key string, parts []transferlink.Range, size int64, executable bool) (Assembled, error)
	// RemoveChunkStaging removes the staging directory after the adoption
	// checks; an absent directory is success.
	RemoveChunkStaging(ctx context.Context, parent, key string) error
	// CollectStaging removes at most 16 stale staging directories of the
	// parent, never the one for excludeKey (empty for none). It returns how
	// many were removed. Callers ignore its error.
	CollectStaging(ctx context.Context, parent, excludeKey string) (int, error)
	// DiskAvailable returns the bytes available on the filesystem of parent;
	// ok is false when the result is unavailable or unparsable (skip the
	// check).
	DiskAvailable(ctx context.Context, parent string) (avail int64, ok bool, err error)

	// StatSource returns the size and whole-second mtime of a regular file.
	StatSource(ctx context.Context, path string) (SourceStat, error)
	// ReadRange streams part of a regular file into dst and returns the byte
	// count. grid is the current chunk size S and fileSize the remote size;
	// dd is used when part.Off is a multiple of grid and the part is a whole
	// block or the tail of the file, else tail/head. A count different from
	// part.Len without a transport error is ClassIntegrity.
	ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error)
}

// The types, values and helpers below are implemented in the subpackages and
// are the public API of this package.

// Capability verdicts of the chunked mode.
type (
	// ReadMode names the verified range-read primitive of a remote host.
	ReadMode = core.ReadMode
	// MtimeMode names the verified stat flavour reporting size and mtime.
	MtimeMode = core.MtimeMode
	// ChunkCaps is the chunked-mode verdict of the capability probe.
	ChunkCaps = core.ChunkCaps
)

// Verified range-read primitives and stat flavours.
const (
	ReadNone  = core.ReadNone
	ReadDD    = core.ReadDD
	ReadTail  = core.ReadTail
	MtimeNone = core.MtimeNone
	MtimeGNU  = core.MtimeGNU
	MtimeBSD  = core.MtimeBSD
)

// Results of the chunked operations.
type (
	// Assembled describes the file produced by AssembleStaging.
	Assembled = chunk.Assembled
	// StagingState is the verdict of EnsureStaging.
	StagingState = chunk.StagingState
	// PartResult is the verdict of UploadPart.
	PartResult = chunk.PartResult
	// StagingListing is the caller-side coverage built from a staging listing.
	StagingListing = chunk.StagingListing
	// SourceStat is the size and whole-second modification time of a remote file.
	SourceStat = chunk.SourceStat
)

// Staging verdicts of EnsureStaging.
const (
	StagingCreated = chunk.StagingCreated
	StagingReused  = chunk.StagingReused
	StagingForeign = chunk.StagingForeign
)

// Remote exit codes of the chunked templates.
const (
	ExitStageForeign = chunk.ExitStageForeign
	ExitStageMissing = chunk.ExitStageMissing
	ExitPartMissing  = chunk.ExitPartMissing
)

// StagingKey derives the staging key of a chunked transfer.
func StagingKey(fields ...string) string { return chunk.StagingKey(fields...) }

// IsStageForeign reports whether err is a remote exit of ExitStageForeign.
func IsStageForeign(err error) bool { return chunk.IsStageForeign(err) }

// IsStageMissing reports whether err is a remote exit of ExitStageMissing.
func IsStageMissing(err error) bool { return chunk.IsStageMissing(err) }

// IsPartMissing reports whether err is a remote exit of ExitPartMissing.
func IsPartMissing(err error) bool { return chunk.IsPartMissing(err) }

// MaxListedParts is the bound on staging entries for a file limit.
func MaxListedParts(l transfercore.Limits) int { return chunk.MaxListedParts(l) }

// LinkFailure returns the error of a command session that ended without a
// remote exit status: a drop in the terms of docs/FILE-TRANSFER.md.
func LinkFailure() *transfercore.Error { return core.LinkFailure() }

// IsLinkFailure reports whether err is a LinkFailure.
func IsLinkFailure(err error) bool { return core.IsLinkFailure(err) }

// FormatManifest serializes a canonical manifest stream.
func FormatManifest(m transfercore.Manifest, l transfercore.Limits) ([]byte, error) {
	return tree.FormatManifest(m, l)
}

// ParseManifest parses a canonical manifest stream as written by FormatManifest.
func ParseManifest(data []byte, l transfercore.Limits) (transfercore.Manifest, error) {
	return tree.ParseManifest(data, l)
}
