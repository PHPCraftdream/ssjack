package transferengine

import (
	"context"
	"encoding/hex"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// downloadDir copies a remote directory tree into fresh local staging next
// to the destination and publishes it atomically. The remote preflight
// manifest is the expected tree: extraction verifies sizes, hashes and the
// exact entry set while streaming, so a remote tree that changes during the
// transfer fails as an integrity error. Nothing is published on any failure
// and the staging is aborted on every failure path including cancellation.
// Progress reports expected payload bytes per phase; extraction has no
// incremental hook.
func (e *Engine) downloadDir(ctx context.Context, root *transferlocal.Root, remote, local string, expected transfercore.Manifest, overwrite bool, progress func(Progress)) (Result, error) {
	expected.Normalize()
	if err := expected.CheckLimits(e.limits); err != nil {
		return Result{}, err
	}
	files, dirs, bytes := expected.Totals()

	staging, err := transferlocal.NewStaging(local, root.Dir(), overwrite)
	if err != nil {
		return Result{}, classify(ctx, err)
	}
	// Abort removes the staging on every failure path, including
	// cancellation; it is a no-op after a successful publish.
	defer func() { _ = staging.Abort() }()

	report(progress, transfercore.PhaseTransfer, 0)
	var computed transfercore.Manifest
	consumerErr, producerErr := pipeStream(
		func(w io.Writer) error { return e.remote.TarOut(ctx, remote, w) },
		func(r io.Reader) error {
			var extractErr error
			computed, extractErr = transferlocal.ExtractTar(r, staging, &expected, e.limits)
			if extractErr == nil {
				// tar pads the archive after its end marker; drain a bounded
				// tail so the remote writer is not failed by a closed pipe.
				_, _ = io.CopyN(io.Discard, r, drainLimit)
			}
			return extractErr
		},
	)
	// A cancelled transfer outranks both sides; otherwise the extraction
	// verdict decides (it also carries a truncated remote stream), and a
	// producer error that never reached the extractor is the aftermath of
	// an extraction failure.
	if ctx.Err() != nil {
		return Result{}, transfercore.Fail(transfercore.ClassCancelled, msgCancelled)
	}
	if consumerErr != nil {
		return Result{}, consumerErr
	}
	if producerErr != nil {
		return Result{}, producerErr
	}

	report(progress, transfercore.PhaseVerify, bytes)
	report(progress, transfercore.PhasePublish, bytes)
	if err := staging.Publish(transferlocal.KindDir); err != nil {
		return Result{}, classify(ctx, err)
	}

	report(progress, transfercore.PhaseCleanup, bytes)
	digest := computed.Digest()
	return Result{
		Kind:           KindDir,
		Files:          files,
		Dirs:           dirs,
		Bytes:          bytes,
		ManifestSHA256: hex.EncodeToString(digest[:]),
	}, nil
}
