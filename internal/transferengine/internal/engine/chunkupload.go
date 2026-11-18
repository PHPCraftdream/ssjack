package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// minChunkedFile is the smallest file worth chunking: below two minimum
// chunks the per-part sessions cost more than the resume saves, so such a file
// keeps the whole-stream behaviour and a drop fails it as before.
const minChunkedFile = 2 * transferlink.MinChunk

// uploadJob is the state of one single-file upload: the whole-stream first
// attempt (engine.go) and, after a link drop, the chunked resumable loop
// (this file). It lives for one Upload call; everything that outlives the call
// is in the remote staging directory and the Engine's link profile.
//
// The reporting state (report.go) is guarded by its own lock because the
// SSH stdin copy of a stream reports progress from its own goroutine. Every
// other field belongs to the goroutine that runs the job.
type uploadJob struct {
	jobReport
	ctx        context.Context
	file       *os.File
	mtimeNs    int64
	mtimeKnown bool
	local      string
	remote     string
	parent     string
	overwrite  bool
	executable bool

	chunkOK      bool // chunked mode may be used for this job
	usedChunk    bool // chunked mode was entered
	key          string
	stagingKnown bool // the keyed staging directory may exist and is the job's own
	covered      int64
	needSync     bool // the staging must be listed again before the next part
	hashed       bool
	sum          [32]byte
	diskChecked  bool
	restarted    bool
	announced    bool
	streamed     bool // a whole-stream attempt was made
	usedProfile  bool // the job consulted the link profile
}

// run executes the job: preflight, then attempts until the file is published
// or the job fails, then the end-of-job bookkeeping.
func (j *uploadJob) run() (Result, error) {
	var res Result
	err := j.preflight()
	if err == nil {
		res, err = j.loop()
	}
	return j.finish(res, err)
}

// preflight prepares the chunked mode of a chunk-capable target: it derives
// the staging key, collects stale staging of the parent (its failure is
// ignored) and, for a file worth chunking, looks at the staging directory of
// this very transfer. A directory that already holds valid parts forces
// chunked mode; a foreign object at the staging name disables it.
func (j *uploadJob) preflight() error {
	if j.e.chunk == nil || !j.e.chunk.ChunkCaps().Upload() {
		return nil
	}
	j.key = transferremote.StagingKey(j.e.target, j.remote, j.local,
		strconv.FormatInt(j.size, 10), strconv.FormatInt(j.mtimeNs, 10))
	_, _ = j.e.chunk.CollectStaging(j.ctx, j.parent, j.key)
	if j.ctx.Err() != nil {
		return cancelled()
	}
	if j.size < minChunkedFile || !j.mtimeKnown {
		return nil
	}
	j.chunkOK = true
	j.usedProfile = true
	j.needSync = true
	return j.lookup()
}

// lookup lists the staging directory of this transfer, if there is one.
func (j *uploadJob) lookup() error {
	listing, err := j.e.chunk.ListStaging(j.ctx, j.parent, j.key, j.size)
	switch {
	case err == nil:
		j.stagingKnown = true
		if listing.Overflow {
			if j.e.chunk.RemoveChunkStaging(j.ctx, j.parent, j.key) == nil {
				j.stagingKnown = false
			}
			return nil
		}
		j.takeListing(listing)
		if len(j.parts) > 0 {
			var largest int64
			for _, p := range j.parts {
				largest = max(largest, p.Len)
			}
			j.e.profile.ForceChunked(largest)
			j.needSync = false
		}
	case j.ctx.Err() != nil:
		return cancelled()
	case transferremote.IsStageForeign(err):
		j.chunkOK = false
	}
	return nil
}

// loop runs attempts until the upload is published or fails. The first
// attempt is the whole stream; after a link drop the profile decides between
// another stream and chunked mode, and eight attempts without progress end the
// job as link_unstable.
func (j *uploadJob) loop() (Result, error) {
	for {
		if j.chunkOK {
			if j.ctx.Err() != nil {
				return Result{}, cancelled()
			}
			if j.e.profile.GiveUp() {
				return Result{}, transfercore.Fail(transfercore.ClassLinkUnstable, transfercore.MsgLinkUnstable)
			}
		}
		if chunked, planned := j.plan(); chunked {
			if res, final, err := j.chunkStep(planned); final {
				return res, err
			}
			continue
		}
		res, link, err := j.streamAttempt()
		if err == nil {
			return res, nil
		}
		if !link || !j.chunkOK {
			return Result{}, err
		}
	}
}

// plan asks the link profile for the next attempt. Chunked mode is used when
// the profile says so, and always while the staging holds parts: those bytes
// are never discarded, so the last gap then goes as one single part
// (planned == 0 means the whole gap).
func (j *uploadJob) plan() (chunked bool, planned int64) {
	return j.nextStep(j.chunkOK, j.covered)
}

// chunkStep makes one step of the chunked loop. final reports that res and err
// are the outcome of the job; otherwise the loop continues (a part was stored,
// or an attempt ended in a drop that the profile has been told about).
func (j *uploadJob) chunkStep(planned int64) (res Result, final bool, err error) {
	if !j.hashed {
		if err := j.hashSource(); err != nil {
			return Result{}, true, err
		}
	}
	j.usedChunk = true
	j.setMode(ModeChunked)
	if j.needSync {
		ok, err := j.sync()
		if err != nil {
			return Result{}, true, err
		}
		if !ok {
			return Result{}, false, nil
		}
	}
	if planned > 0 {
		j.setChunkLen(planned)
	}
	if !j.announced {
		// Show the bytes found on resume at once.
		j.announced = true
		j.emit(transfercore.PhaseTransfer, j.covered)
	}
	if !j.diskChecked {
		j.diskChecked = true
		short, err := j.diskShort()
		if err != nil {
			return Result{}, true, err
		}
		if short {
			return Result{}, true, transfercore.Fail(transfercore.ClassLimit, msgDiskShort)
		}
	}
	rg, more, err := transferlink.NextRange(j.size, j.parts, planned)
	if err != nil {
		return Result{}, true, transfercore.Fail(transfercore.ClassInternal, msgFailed)
	}
	if !more {
		return j.assemble()
	}
	if planned <= 0 {
		planned = rg.Len
	}
	return j.sendPart(rg, planned)
}

// hashSource computes the SHA-256 of the whole source in one local pass, the
// anchor of the final verification. The source must still be the file the
// staging key was derived from.
func (j *uploadJob) hashSource() error {
	h := sha256.New()
	n, err := io.Copy(h, &ctxReader{ctx: j.ctx, r: io.NewSectionReader(j.file, 0, j.size)})
	if err != nil {
		return classify(j.ctx, err)
	}
	if n != j.size || j.sourceChanged() {
		return transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}
	copy(j.sum[:], h.Sum(nil))
	j.hashed = true
	return nil
}

// sourceChanged reports whether the open source no longer has the size and
// modification time the staging key was derived from.
func (j *uploadJob) sourceChanged() bool {
	info, err := j.file.Stat()
	return err != nil || info.Size() != j.size || info.ModTime().UnixNano() != j.mtimeNs
}

// sync makes the staging directory exist and rebuilds the coverage from its
// listing. ok is false when the step ended in a drop (already reported to the
// profile) or restarted a corrupt staging: the loop then tries again.
func (j *uploadJob) sync() (ok bool, err error) {
	c := j.e.chunk
	start := j.e.now()
	j.stagingKnown = true
	state, err := c.EnsureStaging(j.ctx, j.parent, j.key)
	if err != nil {
		return j.syncFailed(err, start)
	}
	j.e.profile.ConnectionSetup(j.e.now().Sub(start))
	if state == transferremote.StagingForeign {
		return j.foreignStaging()
	}
	listing, err := c.ListStaging(j.ctx, j.parent, j.key, j.size)
	if err != nil {
		switch {
		case j.ctx.Err() != nil:
			return false, cancelled()
		case transferremote.IsStageMissing(err):
			j.noteDrop(0, j.e.now().Sub(start))
			return false, nil
		case transferremote.IsStageForeign(err):
			return j.foreignStaging()
		}
		return j.syncFailed(err, start)
	}
	if listing.Overflow {
		// A corrupt staging is removed and the job restarts from zero once.
		if j.restarted {
			return false, remoteFailed()
		}
		j.restarted = true
		j.parts, j.covered = nil, 0
		j.refreshCounts()
		if err := c.RemoveChunkStaging(j.ctx, j.parent, j.key); err != nil {
			return j.syncFailed(err, start)
		}
		return false, nil
	}
	j.takeListing(listing)
	j.needSync = false
	return true, nil
}

// foreignStaging handles a foreign object at the staging name, which is never
// adopted, written to or removed. Before any stream was tried the job falls
// back to the whole stream; after a link failure it fails with remote_failed.
func (j *uploadJob) foreignStaging() (bool, error) {
	j.stagingKnown = false
	if !j.streamed && len(j.parts) == 0 {
		j.chunkOK = false
		return false, nil
	}
	return false, remoteFailed()
}

// syncFailed handles an error of a staging lookup session: a link failure is
// a drop, anything else ends the job.
func (j *uploadJob) syncFailed(err error, start time.Time) (bool, error) {
	if j.ctx.Err() != nil {
		return false, cancelled()
	}
	if transferremote.IsLinkFailure(err) {
		j.noteDrop(0, j.e.now().Sub(start))
		return false, nil
	}
	return false, classify(j.ctx, err)
}

// takeListing adopts a staging listing: the accepted parts become the
// coverage and the ignored entries are removed (best effort, they are not in
// the coverage either way).
func (j *uploadJob) takeListing(l transferremote.StagingListing) {
	if len(l.Remove) > 0 {
		_ = j.e.chunk.RemoveStagingEntries(j.ctx, j.parent, j.key, l.Remove)
	}
	j.parts = append([]transferlink.Range(nil), l.Parts...)
	j.covered = 0
	for _, p := range j.parts {
		j.covered += p.Len
	}
	j.refreshCounts()
}

// diskShort reports whether the destination's filesystem lacks the room for
// the rest of the parts plus the assembled file: (size - bytes in valid parts)
// + size. An unknown answer skips the check.
func (j *uploadJob) diskShort() (bool, error) {
	c := j.e.chunk
	if !c.ChunkCaps().DF {
		return false, nil
	}
	avail, ok, err := c.DiskAvailable(j.ctx, j.parent)
	if err != nil {
		if j.ctx.Err() != nil {
			return false, cancelled()
		}
		return false, nil
	}
	if !ok {
		return false, nil
	}
	return avail < spaceNeeded(j.size, j.covered), nil
}

// sendPart uploads one part read from the open source.
func (j *uploadJob) sendPart(rg transferlink.Range, planned int64) (Result, bool, error) {
	if len(j.parts) >= transferremote.MaxListedParts(j.e.limits) {
		return Result{}, true, transfercore.Fail(transfercore.ClassLimit, msgLimitExceeded)
	}
	if j.sourceChanged() {
		return Result{}, true, transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}
	j.beginAttempt(ModeChunked)
	j.setChunkLen(planned)
	src := &countedReader{r: io.NewSectionReader(j.file, rg.Off, rg.Len)}
	start := j.e.now()
	sess, wctx := j.e.stall.Start(j.ctx)
	res, err := j.e.chunk.UploadPart(wctx, j.parent, j.key, rg, sess.Reader(src))
	err = j.stallError(err, sess.Stop())
	elapsed := j.e.now().Sub(start)
	if err != nil {
		return j.sessionFailed(err, src.count(), elapsed, true)
	}
	if !res.Stored {
		return j.partShort(rg, src.count(), elapsed)
	}
	j.parts = append(j.parts, rg)
	j.covered += rg.Len
	j.refreshCounts()
	data := elapsed - j.e.profile.Snapshot().Setup
	if data <= 0 {
		data = elapsed
	}
	j.e.profile.ChunkDone(rg.Len, data)
	j.emit(transfercore.PhaseTransfer, j.covered)
	return Result{}, false, nil
}

// partShort handles a part session that ended normally with a byte count
// other than the part length. A source that ran out of bytes is a changed
// source; a remote that counted fewer bytes than it was sent gets its disk
// checked and otherwise counts as an attempt without progress.
func (j *uploadJob) partShort(rg transferlink.Range, sent int64, elapsed time.Duration) (Result, bool, error) {
	if sent < rg.Len {
		return Result{}, true, transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}
	short, err := j.diskShort()
	if err != nil {
		return Result{}, true, err
	}
	if short {
		return Result{}, true, transfercore.Fail(transfercore.ClassLimit, msgDiskShort)
	}
	j.noteDrop(0, elapsed)
	j.needSync = true
	return Result{}, false, nil
}

// sessionFailed handles the error of a part, assembly or publication
// session. A link failure, and a staging or part that vanished, are drops: the
// profile is told, the staging is listed again and the loop goes on. A
// foreign staging fails the job; so does any other remote status, after a
// disk re-check for a part session (a full disk shows up there).
func (j *uploadJob) sessionFailed(err error, sent int64, life time.Duration, part bool) (Result, bool, error) {
	if j.ctx.Err() != nil {
		return Result{}, true, cancelled()
	}
	switch {
	case transferremote.IsLinkFailure(err):
		j.noteDrop(sent, life)
	case transferremote.IsStageMissing(err), transferremote.IsPartMissing(err):
		j.noteDrop(0, life)
	case transferremote.IsStageForeign(err):
		j.stagingKnown = false
		return Result{}, true, remoteFailed()
	default:
		if part {
			short, derr := j.diskShort()
			if derr != nil {
				return Result{}, true, derr
			}
			if short {
				return Result{}, true, transfercore.Fail(transfercore.ClassLimit, msgDiskShort)
			}
		}
		return Result{}, true, classify(j.ctx, err)
	}
	j.needSync = true
	return Result{}, false, nil
}

// assemble concatenates the parts remotely, compares the assembled file with
// the local whole-file hash and publishes it. A drop keeps the staging and
// reassembles into a new temporary name on the next attempt.
func (j *uploadJob) assemble() (Result, bool, error) {
	if j.sourceChanged() {
		return Result{}, true, transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}
	if err := transferlink.ValidateTiling(j.size, j.parts); err != nil {
		return Result{}, true, transfercore.Fail(transfercore.ClassInternal, msgFailed)
	}
	j.beginAttempt(ModeChunked)
	j.emit(transfercore.PhaseVerify, j.covered)
	start := j.e.now()
	asm, err := j.e.chunk.AssembleStaging(j.ctx, j.parent, j.key, j.parts, j.size, j.executable)
	if err != nil {
		return j.sessionFailed(err, 0, j.e.now().Sub(start), false)
	}
	if asm.Size != j.size || asm.SHA256 != j.sum {
		return Result{}, true, transfercore.Fail(transfercore.ClassIntegrity, msgRemoteMismatch)
	}
	j.emit(transfercore.PhasePublish, j.size)
	if err := j.e.remote.PublishFile(j.ctx, asm.Path, j.remote, j.overwrite); err != nil {
		return j.sessionFailed(err, 0, j.e.now().Sub(start), false)
	}
	j.emit(transfercore.PhaseCleanup, j.size)
	return Result{Kind: KindFile, Files: 1, Bytes: j.size, SHA256: hex.EncodeToString(j.sum[:])}, true, nil
}

// noteStreamDone feeds the throughput of a finished stream to the profile.
func (j *uploadJob) noteStreamDone(bytes int64, elapsed time.Duration) {
	if j.chunkOK {
		j.e.profile.StreamProgress(bytes, elapsed)
	}
}

// finish ends the job: the link profile learns that the transfer ended, the
// job's own staging is removed unless the job is resumable, and the
// chunked-mode fields are filled in when the job left the plain stream.
func (j *uploadJob) finish(res Result, err error) (Result, error) {
	j.endProfile(j.usedProfile, err)
	j.cleanupStaging(err)
	return j.decorate(res, err, j.usedChunk, j.covered)
}

// cleanupStaging removes the job's own chunk staging, with a fresh bounded
// context so cancellation cannot prevent it, unless the job ended in
// link_unstable: that staging stays for the next call to resume. A failed
// removal never changes the outcome (staging idle for a day is collected by a
// later transfer into the same parent).
func (j *uploadJob) cleanupStaging(err error) {
	if !j.stagingKnown {
		return
	}
	if err != nil && transfercore.ClassOf(err) == transfercore.ClassLinkUnstable {
		return
	}
	cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	_ = j.e.chunk.RemoveChunkStaging(cctx, j.parent, j.key)
}

func cancelled() error {
	return transfercore.Fail(transfercore.ClassCancelled, msgCancelled)
}

func remoteFailed() error {
	return transfercore.Fail(transfercore.ClassRemoteFailed, msgRemoteFailed)
}

// ctxReader fails a read once the context is done, so a long local pass
// notices cancellation.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// countedReader counts the bytes read from r. The count is read after the
// remote call returned, while the SSH stdin copy may still be reading.
type countedReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countedReader) count() int64 { return c.n.Load() }
