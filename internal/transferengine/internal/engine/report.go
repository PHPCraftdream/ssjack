package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"math"
	"path"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// jobReport is the state a single-file job shares in both directions: the
// engine, the file size, the verified parts and the content-free reporting
// fields (mode, attempts, chunk size, part counts, monotone bytes) that
// Progress and Result carry. uploadJob and downloadJob embed it; everything
// that depends on the direction stays in the job.
//
// The reporting fields are guarded by mu because a stream reports progress
// from the goroutine that moves its bytes. Every other field belongs to the
// goroutine that runs the job.
type jobReport struct {
	e        *Engine
	size     int64
	progress func(Progress)
	parts    []transferlink.Range

	mu          sync.Mutex
	mode        string
	attempts    int
	chunkLen    int64
	chunksDone  int
	chunksTotal int
	high        int64
}

// tele is a copy of the reporting state.
type tele struct {
	mode     string
	chunkLen int64
	done     int
	total    int
	attempts int
	bps      int64
}

func (j *jobReport) telemetry() tele {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.teleLocked()
}

func (j *jobReport) teleLocked() tele {
	t := tele{mode: j.mode, chunkLen: j.chunkLen, done: j.chunksDone, total: j.chunksTotal, attempts: j.attempts}
	if j.e.chunk != nil {
		t.bps = int64(math.Round(j.e.profile.Snapshot().Speed))
	}
	return t
}

// emit reports progress. The reported bytes never decrease. The callback runs
// under the reporting lock, so calls are serialised and ordered; it must not
// call back into the engine.
func (j *jobReport) emit(phase string, bytes int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.high = max(j.high, bytes)
	if j.progress == nil {
		return
	}
	t := j.teleLocked()
	j.progress(Progress{
		Phase: phase, Bytes: j.high,
		Mode: t.mode, ChunkBytes: t.chunkLen, ChunksDone: t.done, ChunksTotal: t.total,
		Attempts: t.attempts, BytesPerSecond: t.bps,
	})
}

// beginAttempt counts one attempt and records its mode.
func (j *jobReport) beginAttempt(mode string) {
	j.mu.Lock()
	j.attempts++
	j.mode = mode
	if mode == ModeStream {
		j.chunkLen = 0
	}
	j.mu.Unlock()
	j.refreshCounts()
}

func (j *jobReport) setMode(mode string) {
	j.mu.Lock()
	j.mode = mode
	j.mu.Unlock()
}

// setChunkLen records the chunk size in use and re-estimates the part count.
func (j *jobReport) setChunkLen(s int64) {
	j.mu.Lock()
	j.chunkLen = s
	j.mu.Unlock()
	j.refreshCounts()
}

// refreshCounts recomputes chunks_done and chunks_total: the parts verified so
// far plus an estimate of the parts the open gaps still need at the current
// chunk size. A plain stream with no parts reports neither.
func (j *jobReport) refreshCounts() {
	done := len(j.parts)
	total := done
	j.mu.Lock()
	s := j.chunkLen
	plain := j.mode == ModeStream && done == 0
	j.mu.Unlock()
	if plain {
		done, total = 0, 0
	} else if gaps, err := transferlink.Gaps(j.size, j.parts); err == nil {
		for _, g := range gaps {
			if s > 0 {
				total += int((g.Len + s - 1) / s)
			} else {
				total++
			}
		}
	}
	j.mu.Lock()
	j.chunksDone, j.chunksTotal = done, total
	j.mu.Unlock()
}

// nextStep asks the link profile for the next attempt. Chunked mode is used
// when the profile says so, and always while parts exist: those bytes are never
// discarded, so the last gap then goes as one single part (planned == 0 means
// the whole gap).
func (j *jobReport) nextStep(chunkOK bool, covered int64) (chunked bool, planned int64) {
	if !chunkOK {
		return false, 0
	}
	step := j.e.profile.Decide(j.size - covered)
	if step.Mode == transferlink.ModeChunked {
		return true, step.Len
	}
	return len(j.parts) > 0, 0
}

// noteDrop tells the link profile that an attempt ended without a remote exit
// status. bytes is what the attempt moved over the wire and life how long its
// connection lived; an attempt that moved no byte did not establish anything
// to learn from and only counts as an attempt without progress.
func (j *jobReport) noteDrop(bytes int64, life time.Duration) {
	p := j.e.profile
	if bytes <= 0 {
		p.Dropped(0, life, transferlink.FailSetup)
		return
	}
	p.StreamProgress(bytes, life)
	p.Dropped(bytes, life, transferlink.FailLink)
}

// endProfile tells the link profile that the transfer ended, when the job
// consulted it.
func (j *jobReport) endProfile(used bool, err error) {
	if !used {
		return
	}
	if err == nil {
		j.e.profile.Succeeded()
	} else {
		j.e.profile.BeginTransfer()
	}
}

// decorate fills the chunked-mode fields of the outcome when the job left the
// plain first stream: it entered chunked mode or needed more than one attempt.
// A failed chunked job returns a Result holding only the verified bytes and
// these fields.
func (j *jobReport) decorate(res Result, err error, usedChunk bool, covered int64) (Result, error) {
	t := j.telemetry()
	if !usedChunk && t.attempts <= 1 {
		return res, err
	}
	if err != nil {
		res = Result{Bytes: covered}
	}
	res.Mode, res.ChunkBytes = t.mode, t.chunkLen
	res.ChunksDone, res.ChunksTotal = t.done, t.total
	res.Attempts, res.BytesPerSecond = t.attempts, t.bps
	return res, err
}

// spaceNeeded is the room a chunked transfer needs on the destination side:
// the bytes not yet in valid parts, plus the assembled file of the whole size.
func spaceNeeded(size, covered int64) int64 {
	need := size - covered
	if need > math.MaxInt64-size {
		return math.MaxInt64
	}
	return need + size
}

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

func limitExceeded() error {
	return transfercore.Fail(transfercore.ClassLimit, msgLimitExceeded)
}

// hashingReader hashes and counts what is actually read from the local source
// while it streams to the remote side, and fails the stream once the byte
// limit is crossed so an over-limit transfer cannot complete.
type hashingReader struct {
	src    io.Reader
	max    int64
	onRead func(int64) // optional streaming progress hook

	// mu guards the fields below: the SSH stdin copy goroutine may still be
	// reading after the remote call has returned.
	mu  sync.Mutex
	h   hash.Hash
	n   int64
	err error
}

func newHashingReader(src io.Reader, max int64) *hashingReader {
	return &hashingReader{src: src, h: sha256.New(), max: max}
}

func (r *hashingReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	failed := r.err
	r.mu.Unlock()
	if failed != nil {
		return 0, failed
	}
	n, err := r.src.Read(p)
	if n > 0 {
		r.mu.Lock()
		_, _ = r.h.Write(p[:n])
		r.n += int64(n)
		total := r.n
		if total > r.max {
			r.err = limitExceeded()
			failed = r.err
		}
		r.mu.Unlock()
		if failed != nil {
			return n, failed
		}
		if r.onRead != nil {
			r.onRead(total)
		}
	}
	return n, err
}

func (r *hashingReader) count() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func (r *hashingReader) failure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *hashingReader) digest() [32]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out [32]byte
	copy(out[:], r.h.Sum(nil))
	return out
}

// hashingWriter hashes and counts what is actually written into the local
// staging payload while the remote stream arrives. A chunk that would exceed
// the byte limit is not written and fails the stream.
type hashingWriter struct {
	dst     io.Writer
	h       hash.Hash
	n       int64
	max     int64
	err     error
	onWrite func(int64) // optional streaming progress hook
}

func newHashingWriter(dst io.Writer, max int64) *hashingWriter {
	return &hashingWriter{dst: dst, h: sha256.New(), max: max}
}

func (w *hashingWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.n > w.max-int64(len(p)) {
		w.err = limitExceeded()
		return 0, w.err
	}
	n, err := w.dst.Write(p)
	if n > 0 {
		_, _ = w.h.Write(p[:n])
		w.n += int64(n)
		if w.onWrite != nil {
			w.onWrite(w.n)
		}
	}
	if err != nil {
		w.err = err
		return n, err
	}
	return n, nil
}

func (w *hashingWriter) digest() [32]byte {
	var out [32]byte
	copy(out[:], w.h.Sum(nil))
	return out
}

// pipeStream runs producer in a goroutine writing one end of an io.Pipe and
// consumes the other end with consume. A producer failure is carried into
// the consumer through the pipe (CloseWithError); a consumer failure or any
// early return closes the read end, so a producer blocked in Write cannot
// deadlock. The producer is always waited for before pipeStream returns, so
// no goroutine outlives the transfer step. Callers decide the outcome from
// the consumer side first: a producer error that never reached the consumer
// is the aftermath of the consumer's own failure.
func pipeStream(producer func(io.Writer) error, consume func(io.Reader) error) (consumerErr, producerErr error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := producer(pw)
		if err != nil {
			_ = pw.CloseWithError(err)
		} else {
			_ = pw.Close()
		}
		done <- err
	}()
	consumerErr = consume(pr)
	_ = pr.Close()
	producerErr = <-done
	return consumerErr, producerErr
}
