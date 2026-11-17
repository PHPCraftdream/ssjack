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
//
// A single file whose stream drops on a link that cannot carry it within a
// connection's lifetime continues in chunked, resumable mode inside the same
// call (see chunkdownload.go); directories always move as one whole stream.
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

// downloadFile is the single-file flow: run the job, which streams the remote
// file into the staged payload first, requires size and hash to equal the
// pre-stat values and publishes, and falls back to chunked mode after a link
// drop.
func (e *Engine) downloadFile(ctx context.Context, root *transferlocal.Root, remote, local string, statSize int64, statHash [32]byte, overwrite bool, progress func(Progress)) (Result, error) {
	if statSize > e.limits.MaxBytes {
		return Result{}, transfercore.Fail(transfercore.ClassLimit, msgLimitExceeded)
	}
	j := &downloadJob{
		jobReport: jobReport{e: e, size: statSize, progress: progress, mode: ModeStream},
		ctx:       ctx, root: root,
		remote: remote, local: local, sum: statHash, overwrite: overwrite,
	}
	return j.run()
}

// streamAttempt is one whole-file stream: create local staging, stream the
// remote file into the payload while hashing, verify against the pre-stat
// values, publish. The attempt's own staging is always removed on failure.
// link reports that the stream itself ended without a remote exit status, the
// only failure after which another attempt makes sense; the profile has then
// been told about the drop when chunked mode is possible.
func (j *downloadJob) streamAttempt() (res Result, link bool, err error) {
	e := j.e
	ctx := j.ctx
	j.streamed = true
	j.beginAttempt(ModeStream)

	staging, err := transferlocal.NewStaging(j.local, j.root.Dir(), j.overwrite)
	if err != nil {
		return Result{}, false, classify(ctx, err)
	}
	// Abort removes the staging on every failure path, including
	// cancellation; it is a no-op after a successful publish.
	defer func() { _ = staging.Abort() }()

	payload, err := staging.CreatePayload()
	if err != nil {
		return Result{}, false, classify(ctx, err)
	}

	j.emit(transfercore.PhaseTransfer, 0)
	writer := newHashingWriter(payload, e.limits.MaxBytes)
	writer.onWrite = func(n int64) { j.emit(transfercore.PhaseTransfer, n) }
	start := e.now()
	_, err = e.remote.ReadFile(ctx, j.remote, writer)
	elapsed := e.now().Sub(start)
	if err != nil {
		_ = payload.Close()
		if writer.err != nil {
			return Result{}, false, classify(ctx, writer.err)
		}
		return Result{}, j.noteStreamError(err, writer.n, start), classify(ctx, err)
	}
	if err := payload.Close(); err != nil {
		return Result{}, false, transfercore.Fail(transfercore.ClassInternal, msgStagedWrite)
	}
	if writer.err != nil {
		return Result{}, false, classify(ctx, writer.err)
	}
	if j.chunkOK {
		e.profile.StreamProgress(writer.n, elapsed)
	}

	j.emit(transfercore.PhaseVerify, writer.n)
	digest := writer.digest()
	if writer.n != j.size || digest != j.sum {
		return Result{}, false, transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}

	j.emit(transfercore.PhasePublish, writer.n)
	if err := staging.Publish(transferlocal.KindFile); err != nil {
		return Result{}, false, classify(ctx, err)
	}

	j.emit(transfercore.PhaseCleanup, writer.n)
	return Result{Kind: KindFile, Files: 1, Dirs: 0, Bytes: writer.n, SHA256: hex.EncodeToString(digest[:])}, false, nil
}
