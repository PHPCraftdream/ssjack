// Package engine composes the remote protocol layer
// (internal/transferremote) and the local safety layer (internal/transferlocal)
// into the single-file operations of docs/FILE-TRANSFER.md: verified, atomic,
// cancellable copies between an owner-approved local root and an approved
// remote path. The file content never passes through the model: results are
// bounded and content-free (counts and a hex SHA-256), errors are
// *transfercore.Error values with fixed messages, and no path, content or
// remote stderr is ever included. The kind is detected from the source
// (engine.go): a regular file is copied as a file, a directory tree as a
// directory, with the same guarantees.
//
// A single-file transfer starts as one whole-file stream. When the connection
// drops and the link profile (internal/transferlink) says the file cannot be
// expected to cross within a connection's lifetime, the same job continues in
// chunked, resumable mode (chunkupload.go for uploads, chunkdownload.go for
// downloads) and still publishes only after a whole-file SHA-256 check. The
// reporting state both directions share is in report.go.
package engine

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/watchdog"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
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
// They are set only for a single-file transfer that left the plain first
// stream: it entered chunked mode or needed more than one attempt. A plain
// stream result, a directory result and the failure of a plain stream keep
// them zero (a consumer reports mode "stream" and one attempt for those). A
// failed chunked transfer returns a Result holding only Bytes (the bytes
// verified at the destination side) and these fields.
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
// destination including parts found on resume. For single-file transfers the
// other fields carry the same chunked-mode values as Result, with Mode set,
// from the transfer phase on (the preflight report precedes the first
// attempt); they are zero for directories.
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
	// StallLimit is how long a byte-moving session of an upload (the whole
	// stream, one part) may deliver no byte before the stall watchdog counts it
	// as a drop. Zero means DefaultStallLimit (60 s); negative is invalid.
	StallLimit time.Duration
	// StallClock drives the watchdog's timer. Nil means the wall clock; tests
	// inject a virtual one.
	StallClock StallClock
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
	stall   watchdog.Config
}

// New validates the limits and returns an Engine over remote with default
// options: an empty target name, a fresh link profile and the wall clock.
func New(remote transferremote.Remote, limits transfercore.Limits) (*Engine, error) {
	return NewWithOptions(remote, limits, Options{})
}

// NewWithOptions is New with the target name, an injectable link profile and
// an injectable clock. A remote that also implements
// transferremote.ChunkRemote enables the chunked modes, when its probed
// capabilities allow them (ChunkCaps.Upload and ChunkCaps.Download).
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
	stall, err := watchdog.NewConfig(opts.StallClock, opts.StallLimit)
	if err != nil {
		return nil, err
	}
	e := &Engine{remote: remote, limits: limits, target: opts.Target, profile: profile, now: now, stall: stall}
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

// StallClock and StallTimer are the watchdog's timer interfaces, re-exported
// under their original names so Options can name them.
type (
	StallClock = watchdog.StallClock
	StallTimer = watchdog.StallTimer
)

// stallError is stallFailure for an upload session.
func (j *uploadJob) stallError(err error, stalled bool) error {
	return watchdog.Failure(j.ctx, err, stalled)
}

// stallError is stallFailure for a download session.
func (j *downloadJob) stallError(err error, stalled bool) error {
	return watchdog.Failure(j.ctx, err, stalled)
}

// Source kind detection. The kind always comes from the source, never from
// the caller. Locally, a source that opens as a regular file is a file and a
// source that only walks as a tree is a directory (Upload dispatches on
// exactly that). Remotely, a path that stats as a regular file is a file and
// a path that only preflights as a tree is a directory.

// remoteSourceKind stats the remote path as a file; when that is refused it
// probes the path as a tree, so a directory source is distinguished from any
// other refusal. size and sum are the file preflight values; manifest is the
// tree preflight of a directory source. When both probes are refused the
// StatFile error is returned.
func remoteSourceKind(ctx context.Context, remote transferremote.Remote, p string) (Kind, int64, [32]byte, transfercore.Manifest, error) {
	size, sum, err := remote.StatFile(ctx, p)
	if err == nil {
		return KindFile, size, sum, transfercore.Manifest{}, nil
	}
	manifest, treeErr := remote.PreflightTree(ctx, p)
	if treeErr == nil {
		return KindDir, 0, [32]byte{}, manifest, nil
	}
	if transfercore.ClassOf(treeErr) == transfercore.ClassLimit {
		return KindFile, 0, [32]byte{}, transfercore.Manifest{}, treeErr
	}
	return KindFile, 0, [32]byte{}, transfercore.Manifest{}, err
}

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
	// The stall watchdog gives the session its own context: a stream that
	// delivers no byte for the limit is cut and reported as a link failure.
	start := e.now()
	sess, wctx := e.stall.Start(ctx)
	_, err = e.remote.ReadFile(wctx, j.remote, sess.Writer(writer))
	err = j.stallError(err, sess.Stop())
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
	sess, wctx := e.stall.Start(ctx)
	_, err = e.remote.WriteFile(wctx, stagedPath, sess.Reader(reader), j.executable)
	err = j.stallError(err, sess.Stop())
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
