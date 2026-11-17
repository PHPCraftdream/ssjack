package transferengine

import (
	"context"
	"encoding/hex"
	"os"
	"path"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
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
//
// A single file whose stream drops on a link that cannot carry it within a
// connection's lifetime continues in chunked, resumable mode inside the same
// call (see chunkupload.go); directories always move as one whole stream.
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
		return e.uploadFile(ctx, file, sizeAtOpen, local, remote, overwrite, progress)
	}
	manifest, walkErr := root.WalkSource(local, e.limits)
	if walkErr != nil {
		return Result{}, walkErr
	}
	return e.uploadDir(ctx, root, manifest, local, remote, overwrite, progress)
}

// uploadFile is the single-file flow: probe, then run the job, which streams
// the opened source first and falls back to chunked mode after a link drop.
func (e *Engine) uploadFile(ctx context.Context, file *os.File, sizeAtOpen int64, local, remote string, overwrite bool, progress func(Progress)) (Result, error) {
	defer func() { _ = file.Close() }()

	if sizeAtOpen > e.limits.MaxBytes {
		return Result{}, transfercore.Fail(transfercore.ClassLimit, msgLimitExceeded)
	}
	executable := sourceExecutable(file)

	if err := e.remote.Probe(ctx); err != nil {
		return Result{}, classify(ctx, err)
	}
	j := &uploadJob{
		jobReport: jobReport{e: e, size: sizeAtOpen, progress: progress, mode: ModeStream},
		ctx:       ctx, file: file,
		local: local, remote: remote, parent: path.Dir(remote),
		overwrite: overwrite, executable: executable,
	}
	if info, err := file.Stat(); err == nil {
		j.mtimeNs = info.ModTime().UnixNano()
		j.mtimeKnown = true
	}
	return j.run()
}

// streamAttempt is one whole-file stream: create staging, stream the source
// while hashing, verify both sides, publish. The attempt's own staging is
// always removed with a fresh context. link reports that the stream itself
// (or the creation of its staging) ended without a remote exit status, the
// only failure after which another attempt makes sense; the profile has then
// been told about the drop when chunked mode is possible.
func (j *uploadJob) streamAttempt() (res Result, link bool, err error) {
	e := j.e
	ctx := j.ctx
	j.streamed = true
	j.beginAttempt(ModeStream)

	start := e.now()
	stagingPath, err := e.remote.CreateStaging(ctx, j.parent)
	if err != nil {
		return Result{}, j.noteStreamError(err, 0, start), classify(ctx, err)
	}
	stagingName := path.Base(stagingPath)
	stagedPath := stagingPath + "/" + stagedFileName
	// Cleanup runs on every path once staging exists; with a fresh context
	// so cancellation cannot prevent it. Its outcome never changes the
	// transfer outcome.
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		_ = e.remote.CleanupStaging(cctx, j.parent, stagingName)
	}()

	j.emit(transfercore.PhaseTransfer, 0)
	reader := newHashingReader(&offsetReader{f: j.file}, e.limits.MaxBytes)
	// The SSH stdin copy may still be reading after the remote call has
	// returned; the flag keeps a late read from reporting a stale phase.
	var active atomic.Bool
	active.Store(true)
	defer active.Store(false)
	reader.onRead = func(n int64) {
		if active.Load() {
			j.emit(transfercore.PhaseTransfer, n)
		}
	}
	// The stall watchdog gives the session its own context: a stream that
	// moves no byte for the limit is cut and reported as a link failure.
	writeStart := e.now()
	wd, wctx := e.stall.start(ctx)
	_, err = e.remote.WriteFile(wctx, stagedPath, &stallReader{r: reader, w: wd}, j.executable)
	err = j.stallError(err, wd.stop())
	elapsed := e.now().Sub(writeStart)
	if err != nil {
		if reader.failure() != nil {
			return Result{}, false, classify(ctx, reader.failure())
		}
		return Result{}, j.noteStreamError(err, reader.count(), writeStart), classify(ctx, err)
	}
	if reader.failure() != nil {
		return Result{}, false, classify(ctx, reader.failure())
	}
	j.noteStreamDone(reader.count(), elapsed)

	j.emit(transfercore.PhaseVerify, reader.count())
	digest := reader.digest()
	if reader.count() != j.size {
		return Result{}, false, transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}
	remoteSize, remoteHash, err := e.remote.StatFile(ctx, stagedPath)
	if err != nil {
		return Result{}, false, classify(ctx, err)
	}
	if remoteSize != reader.count() || remoteHash != digest {
		return Result{}, false, transfercore.Fail(transfercore.ClassIntegrity, msgRemoteMismatch)
	}

	j.emit(transfercore.PhasePublish, reader.count())
	if err := e.remote.PublishFile(ctx, stagedPath, j.remote, j.overwrite); err != nil {
		return Result{}, false, classify(ctx, err)
	}

	j.emit(transfercore.PhaseCleanup, reader.count())
	return Result{Kind: KindFile, Files: 1, Dirs: 0, Bytes: reader.count(), SHA256: hex.EncodeToString(digest[:])}, false, nil
}

// noteStreamError reports whether err is a link failure of the stream and, if
// chunked mode is possible, feeds the drop to the link profile: bytes is what
// the stream read from the source, the lifetime runs from since to now.
func (j *uploadJob) noteStreamError(err error, bytes int64, since time.Time) bool {
	if j.ctx.Err() != nil || !transferremote.IsLinkFailure(err) {
		return false
	}
	if j.chunkOK {
		j.noteDrop(bytes, j.e.now().Sub(since))
	}
	return true
}

// offsetReader reads the file from an offset of its own with ReadAt, so
// concurrent or lingering readers of earlier attempts never share a file
// offset with it.
type offsetReader struct {
	f   *os.File
	off int64
}

func (r *offsetReader) Read(p []byte) (int, error) {
	n, err := r.f.ReadAt(p, r.off)
	r.off += int64(n)
	return n, err
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
