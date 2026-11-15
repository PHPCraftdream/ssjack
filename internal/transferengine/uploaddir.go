package transferengine

import (
	"context"
	"encoding/hex"
	"io"
	"path"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// uploadDir copies a walked local directory tree into a fresh remote staging
// directory next to the destination and publishes it atomically. The walk
// manifest existed before any remote mutation; the tar stream is rebuilt
// from the manifest with size and hash re-verification, the staged tree is
// verified against the manifest on the remote side, and publication is a
// rename of the staging directory itself. Nothing is published on any
// failure and the staging directory is always removed with a fresh bounded
// context. Progress reports tar-stream bytes during the transfer and
// payload bytes afterwards.
func (e *Engine) uploadDir(ctx context.Context, root *transferlocal.Root, manifest transfercore.Manifest, local, remote string, overwrite bool, progress func(Progress)) (Result, error) {
	files, dirs, bytes := manifest.Totals()
	if err := manifest.CheckLimits(e.limits); err != nil {
		return Result{}, err
	}

	if err := e.remote.Probe(ctx); err != nil {
		return Result{}, classify(ctx, err)
	}
	parent := path.Dir(remote)
	stagingPath, err := e.remote.CreateStaging(ctx, parent)
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	stagingName := path.Base(stagingPath)
	// Cleanup runs on every path once staging exists, with a fresh context
	// so cancellation cannot prevent it; its outcome never changes the
	// transfer outcome.
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		_ = e.remote.CleanupStaging(cctx, parent, stagingName)
	}()

	report(progress, transfercore.PhaseTransfer, 0)
	reader := newHashingReader(nil, e.limits.MaxBytes)
	reader.onRead = func(n int64) { report(progress, transfercore.PhaseTransfer, n) }
	consumerErr, producerErr := pipeStream(
		func(w io.Writer) error { return root.BuildTar(w, local, manifest) },
		func(r io.Reader) error {
			reader.src = r
			return e.remote.TarIn(ctx, stagingPath, reader)
		},
	)
	// The reader carries a producer failure injected through the pipe and
	// the byte limit; the TarIn error is the remote verdict; a producer
	// error that never reached the reader is the aftermath of a TarIn
	// failure.
	switch {
	case reader.failure() != nil:
		return Result{}, classify(ctx, reader.failure())
	case consumerErr != nil:
		return Result{}, classify(ctx, consumerErr)
	case producerErr != nil:
		return Result{}, producerErr
	}

	report(progress, transfercore.PhaseVerify, bytes)
	if err := e.remote.VerifyTree(ctx, stagingPath, manifest); err != nil {
		return Result{}, classify(ctx, err)
	}

	report(progress, transfercore.PhasePublish, bytes)
	if err := e.remote.PublishDir(ctx, stagingPath, remote, overwrite); err != nil {
		return Result{}, classify(ctx, err)
	}

	report(progress, transfercore.PhaseCleanup, bytes)
	digest := manifest.Digest()
	return Result{
		Kind:           KindDir,
		Files:          files,
		Dirs:           dirs,
		Bytes:          bytes,
		ManifestSHA256: hex.EncodeToString(digest[:]),
	}, nil
}
