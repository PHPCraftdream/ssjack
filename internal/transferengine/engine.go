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
package transferengine

import (
	"context"
	"errors"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// Kind is the transfer kind, detected from the source, never from the caller.
type Kind int

// The source of a transfer is a regular file or a directory.
const (
	KindFile Kind = iota
	KindDir
)

// Result is the bounded, content-free outcome of one transfer: counts plus the
// hex SHA-256 of the transferred file or of the canonical directory manifest.
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
}

// Progress reports the phase (a transfercore.Phase* constant) and the bytes
// transferred so far.
type Progress struct {
	Phase string
	Bytes int64
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
)

// Engine composes one approved remote target with the configured limits into
// the single-file operations.
type Engine struct {
	remote transferremote.Remote
	limits transfercore.Limits
}

// New validates the limits and returns an Engine over remote.
func New(remote transferremote.Remote, limits transfercore.Limits) (*Engine, error) {
	if remote == nil {
		return nil, transfercore.Fail(transfercore.ClassInternal, "remote transfer layer is not configured")
	}
	if err := limits.Validate(); err != nil {
		return nil, transfercore.Fail(transfercore.ClassInternal, "transfer limits are invalid")
	}
	return &Engine{remote: remote, limits: limits}, nil
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
