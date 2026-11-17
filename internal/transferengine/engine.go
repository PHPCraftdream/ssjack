// Package transferengine composes the remote protocol layer
// (internal/transferremote) and the local safety layer (internal/transferlocal)
// into the single-file operations of docs/FILE-TRANSFER.md: verified, atomic,
// cancellable copies between an owner-approved local root and an approved
// remote path. The file content never passes through the model: results are
// bounded and content-free (counts and a hex SHA-256), errors are
// *transfercore.Error values with fixed messages, and no path, content or
// remote stderr is ever included. The kind is detected from the source
// (kind.go): a regular file is copied as a file, a directory tree as a
// directory, with the same guarantees.
//
// A single-file upload starts as one whole-file stream. When the connection
// drops and the link profile (internal/transferlink) says the file cannot be
// expected to cross within a connection's lifetime, the same job continues in
// chunked, resumable mode (chunkupload.go) and still publishes only after a
// whole-file SHA-256 check.
package transferengine

import (
	"context"
	"errors"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// Kind is the transfer kind, detected from the source, never from the caller.
type Kind int

// The source of a transfer is a regular file or a directory.
const (
	KindFile Kind = iota
	KindDir
)

// Transfer modes reported in Progress.Mode and Result.Mode.
const (
	ModeStream  = "stream"
	ModeChunked = "chunked"
)

// Result is the bounded, content-free outcome of one transfer: counts plus the
// hex SHA-256 of the transferred file or of the canonical directory manifest.
//
// The chunked-mode fields (Mode to BytesPerSecond) are plain integers and a
// mode name, never content, a path or remote output, and zero when absent.
// They are set only for a single-file upload that left the plain first stream:
// it entered chunked mode or needed more than one attempt. A plain stream
// result, a directory result and the failure of a plain stream keep them zero
// (a consumer reports mode "stream" and one attempt for those). A failed
// chunked upload returns a Result holding only Bytes (the bytes verified at the
// destination) and these fields.
type Result struct {
	Kind   Kind
	Files  int
	Dirs   int
	Bytes  int64
	SHA256 string

	// ManifestSHA256 is the hex SHA-256 of the canonical directory
	// manifest (transfercore.Manifest.Digest) for a directory result;
	// empty for a file result.
	ManifestSHA256 string

	// Mode is ModeStream or ModeChunked: how the job moved its bytes last.
	Mode string
	// ChunkBytes is the chunk size S in use, 0 outside chunked mode.
	ChunkBytes int64
	// ChunksDone is the number of parts verified at the destination,
	// including parts found on resume.
	ChunksDone int
	// ChunksTotal is ChunksDone plus an estimate of the parts still needed
	// at the current chunk size.
	ChunksTotal int
	// Attempts counts every attempt of the job: each stream and each chunk
	// session.
	Attempts int
	// BytesPerSecond is the rounded throughput estimate of the link, 0 while
	// unknown.
	BytesPerSecond int64
}

// Progress reports the phase (a transfercore.Phase* constant) and the bytes
// transferred so far. Bytes never decreases within a job: it counts the bytes
// of the running stream and, in chunked mode, the bytes verified at the
// destination including parts found on resume. For single-file uploads the
// other fields carry the same chunked-mode values as Result, with Mode set,
// from the transfer phase on (the preflight report precedes the first
// attempt); they are zero for downloads and directories.
type Progress struct {
	Phase string
	Bytes int64

	Mode           string
	ChunkBytes     int64
	ChunksDone     int
	ChunksTotal    int
	Attempts       int
	BytesPerSecond int64
}

// Options configure NewWithOptions.
type Options struct {
	// Target is the approved target name; it is one of the fields of the
	// chunked-mode staging key, so a resuming keeper must pass the same value.
	Target string
	// Profile is the link profile of the target. Nil creates a fresh one on
	// Now. It must not be shared between engines of different targets.
	Profile *transferlink.Profile
	// Now is the clock of throughput and connection-lifetime measurements.
	// Nil means time.Now; tests inject a virtual clock (the same one as the
	// clock of an injected Profile).
	Now func() time.Time
}

// cleanupTimeout bounds the fresh context used for staging cleanup so that
// cancelling the transfer context cannot prevent the removal.
const cleanupTimeout = 30 * time.Second

// drainLimit bounds the bytes drained after a tar end marker.
const drainLimit = 1 << 20

// Fixed, content-free messages for engine-level failures.
const (
	msgCancelled      = "transfer was cancelled"
	msgFailed         = "transfer failed"
	msgLimitExceeded  = "transfer exceeds the configured limits"
	msgSourceChanged  = "source changed during the transfer"
	msgRemoteMismatch = "remote copy does not match the source"
	msgStagedWrite    = "staged data could not be written"
	msgRemoteFailed   = "remote operation failed"
	msgDiskShort      = "remote destination has too little free space"
)

// Engine composes one approved remote target with the configured limits into
// the single-file operations. One Engine serves every job of its target: it
// owns the link profile, which is safe for concurrent use. Its other fields
// never change after construction.
type Engine struct {
	remote  transferremote.Remote
	chunk   transferremote.ChunkRemote // nil when remote has no chunked layer
	limits  transfercore.Limits
	target  string
	profile *transferlink.Profile
	now     func() time.Time
}

// New validates the limits and returns an Engine over remote with default
// options: an empty target name, a fresh link profile and the wall clock.
func New(remote transferremote.Remote, limits transfercore.Limits) (*Engine, error) {
	return NewWithOptions(remote, limits, Options{})
}

// NewWithOptions is New with the target name, an injectable link profile and
// an injectable clock. A remote that also implements
// transferremote.ChunkRemote enables the chunked upload mode, when its probed
// capabilities allow it.
func NewWithOptions(remote transferremote.Remote, limits transfercore.Limits, opts Options) (*Engine, error) {
	if remote == nil {
		return nil, transfercore.Fail(transfercore.ClassInternal, "remote transfer layer is not configured")
	}
	if err := limits.Validate(); err != nil {
		return nil, transfercore.Fail(transfercore.ClassInternal, "transfer limits are invalid")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	profile := opts.Profile
	if profile == nil {
		profile = transferlink.NewProfile(transferlink.Config{Now: now})
	}
	e := &Engine{remote: remote, limits: limits, target: opts.Target, profile: profile, now: now}
	if chunk, ok := remote.(transferremote.ChunkRemote); ok {
		e.chunk = chunk
	}
	return e, nil
}

// report invokes a possibly nil progress callback.
func report(progress func(Progress), phase string, bytes int64) {
	if progress != nil {
		progress(Progress{Phase: phase, Bytes: bytes})
	}
}

// classify maps a failed engine step to a *transfercore.Error: an already
// classified error passes through unchanged, a failure under a cancelled
// context is ClassCancelled, and anything else is internal via
// transfercore.ClassOf. Raw error text is never exposed.
func classify(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var classified *transfercore.Error
	if errors.As(err, &classified) {
		return err
	}
	if ctx.Err() != nil {
		return transfercore.Fail(transfercore.ClassCancelled, msgCancelled)
	}
	return &transfercore.Error{Class: transfercore.ClassOf(err), Message: msgFailed}
}
