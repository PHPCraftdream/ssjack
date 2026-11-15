package transferengine

import (
	"context"
	"encoding/hex"
	"os"
	"path"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// stagedFileName is the fixed inner name of the staged file inside the
// remote staging directory.
const stagedFileName = "payload"

// Upload copies one regular file or one directory tree from an approved
// local root to an approved remote path. The kind comes from the source: a
// source that opens as a regular file takes the single-file flow, a source
// that only walks as a tree takes the directory flow. Order: validate both
// paths, open the source through the root or walk it through the root
// (confinement, no-follow, type, hard-link and limit rules), refuse an
// over-limit transfer, probe the remote capabilities, create a staging
// directory next to the destination, stream while hashing or verifying what
// is actually transferred, verify the staged copy against the source,
// publish with the overwrite flag, and always remove the staging directory
// with a fresh bounded context. Nothing is published on any failure. The
// staged file lives inside the staging directory under a fixed name,
// mirroring the local layer.
func (e *Engine) Upload(ctx context.Context, root *transferlocal.Root, local, remote string, overwrite bool, progress func(Progress)) (Result, error) {
	if root == nil {
		return Result{}, transfercore.Fail(transfercore.ClassRefusedPath, "transfer root is missing")
	}
	if err := transfercore.ValidateRemotePath(remote, e.limits); err != nil {
		return Result{}, err
	}
	if err := transfercore.ValidateRemotePath(path.Dir(remote), e.limits); err != nil {
		return Result{}, transfercore.Fail(transfercore.ClassRefusedPath, "remote destination leaves no room for staging")
	}
	if err := transfercore.ValidateRelPath(local, e.limits); err != nil {
		return Result{}, err
	}
	report(progress, transfercore.PhasePreflight, 0)

	file, sizeAtOpen, err := root.OpenSourceFile(local)
	if err == nil {
		return e.uploadFile(ctx, file, sizeAtOpen, remote, overwrite, progress)
	}
	manifest, walkErr := root.WalkSource(local, e.limits)
	if walkErr != nil {
		return Result{}, walkErr
	}
	return e.uploadDir(ctx, root, manifest, local, remote, overwrite, progress)
}

// uploadFile is the single-file flow: stream the opened source into the
// staged file, verify sizes and digests on both sides, and publish.
func (e *Engine) uploadFile(ctx context.Context, file *os.File, sizeAtOpen int64, remote string, overwrite bool, progress func(Progress)) (Result, error) {
	defer func() { _ = file.Close() }()

	if sizeAtOpen > e.limits.MaxBytes {
		return Result{}, transfercore.Fail(transfercore.ClassLimit, msgLimitExceeded)
	}
	executable := sourceExecutable(file)

	if err := e.remote.Probe(ctx); err != nil {
		return Result{}, classify(ctx, err)
	}
	parent := path.Dir(remote)
	stagingPath, err := e.remote.CreateStaging(ctx, parent)
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	stagingName := path.Base(stagingPath)
	stagedPath := stagingPath + "/" + stagedFileName
	// Cleanup runs on every path once staging exists; with a fresh context
	// so cancellation cannot prevent it. Its outcome never changes the
	// transfer outcome.
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		_ = e.remote.CleanupStaging(cctx, parent, stagingName)
	}()

	report(progress, transfercore.PhaseTransfer, 0)
	reader := newHashingReader(file, e.limits.MaxBytes)
	reader.onRead = func(n int64) { report(progress, transfercore.PhaseTransfer, n) }
	if _, err := e.remote.WriteFile(ctx, stagedPath, reader, executable); err != nil {
		if reader.failure() != nil {
			return Result{}, classify(ctx, reader.failure())
		}
		return Result{}, classify(ctx, err)
	}
	if reader.failure() != nil {
		return Result{}, classify(ctx, reader.failure())
	}

	report(progress, transfercore.PhaseVerify, reader.count())
	digest := reader.digest()
	if reader.count() != sizeAtOpen {
		return Result{}, transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}
	remoteSize, remoteHash, err := e.remote.StatFile(ctx, stagedPath)
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	if remoteSize != reader.count() || remoteHash != digest {
		return Result{}, transfercore.Fail(transfercore.ClassIntegrity, msgRemoteMismatch)
	}

	report(progress, transfercore.PhasePublish, reader.count())
	if err := e.remote.PublishFile(ctx, stagedPath, remote, overwrite); err != nil {
		return Result{}, classify(ctx, err)
	}

	report(progress, transfercore.PhaseCleanup, reader.count())
	return Result{Kind: KindFile, Files: 1, Dirs: 0, Bytes: reader.count(), SHA256: hex.EncodeToString(digest[:])}, nil
}

// sourceExecutable reads the execute bits from the opened source handle; the
// mode is advisory for the remote file mode and never part of verification.
func sourceExecutable(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&0o111 != 0
}
