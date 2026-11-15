package transferengine

import (
	"context"
	"encoding/hex"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// Download copies one regular file or one remote directory tree into an
// approved local root. The kind comes from the remote source: StatFile for a
// file, PreflightTree for a tree. Order: validate both paths, probe the
// remote capabilities, detect the source kind, refuse an over-limit
// transfer, create local staging next to the destination (existence and
// control-directory checks), stream under the byte limit, require the copy
// to match the source, publish, and abort the staging on every failure
// including cancellation. Nothing is published on any failure.
func (e *Engine) Download(ctx context.Context, root *transferlocal.Root, remote, local string, overwrite bool, progress func(Progress)) (Result, error) {
	if root == nil {
		return Result{}, transfercore.Fail(transfercore.ClassRefusedPath, "transfer root is missing")
	}
	if err := transfercore.ValidateRemotePath(remote, e.limits); err != nil {
		return Result{}, err
	}
	if err := transfercore.ValidateRelPath(local, e.limits); err != nil {
		return Result{}, err
	}
	report(progress, transfercore.PhasePreflight, 0)

	if err := e.remote.Probe(ctx); err != nil {
		return Result{}, classify(ctx, err)
	}
	kind, statSize, statHash, manifest, err := remoteSourceKind(ctx, e.remote, remote)
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	if kind == KindDir {
		return e.downloadDir(ctx, root, remote, local, manifest, overwrite, progress)
	}
	return e.downloadFile(ctx, root, remote, local, statSize, statHash, overwrite, progress)
}

// downloadFile is the single-file flow: stream the remote file into the
// staged payload, require size and hash to equal the pre-stat values, and
// publish.
func (e *Engine) downloadFile(ctx context.Context, root *transferlocal.Root, remote, local string, statSize int64, statHash [32]byte, overwrite bool, progress func(Progress)) (Result, error) {
	if statSize > e.limits.MaxBytes {
		return Result{}, transfercore.Fail(transfercore.ClassLimit, msgLimitExceeded)
	}
	staging, err := transferlocal.NewStaging(local, root.Dir(), overwrite)
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	// Abort removes the staging on every failure path, including
	// cancellation; it is a no-op after a successful publish.
	defer func() { _ = staging.Abort() }()

	payload, err := staging.CreatePayload()
	if err != nil {
		return Result{}, classify(ctx, err)
	}

	report(progress, transfercore.PhaseTransfer, 0)
	writer := newHashingWriter(payload, e.limits.MaxBytes)
	writer.onWrite = func(n int64) { report(progress, transfercore.PhaseTransfer, n) }
	if _, err := e.remote.ReadFile(ctx, remote, writer); err != nil {
		_ = payload.Close()
		if writer.err != nil {
			return Result{}, classify(ctx, writer.err)
		}
		return Result{}, classify(ctx, err)
	}
	if err := payload.Close(); err != nil {
		return Result{}, transfercore.Fail(transfercore.ClassInternal, msgStagedWrite)
	}
	if writer.err != nil {
		return Result{}, classify(ctx, writer.err)
	}

	report(progress, transfercore.PhaseVerify, writer.n)
	digest := writer.digest()
	if writer.n != statSize || digest != statHash {
		return Result{}, transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}

	report(progress, transfercore.PhasePublish, writer.n)
	if err := staging.Publish(transferlocal.KindFile); err != nil {
		return Result{}, classify(ctx, err)
	}

	report(progress, transfercore.PhaseCleanup, writer.n)
	return Result{Kind: KindFile, Files: 1, Dirs: 0, Bytes: writer.n, SHA256: hex.EncodeToString(digest[:])}, nil
}
