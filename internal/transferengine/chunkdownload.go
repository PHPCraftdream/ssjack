package transferengine

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// Fixed, content-free messages of the chunked download.
const (
	msgStagingForeign = "local staging path is occupied by a foreign object"
	msgLocalDiskShort = "local destination has too little free space"
)

// statSourceTries bounds the attempts of the preflight look at the remote
// file: a link drop there does not yet cost a transfer attempt.
const statSourceTries = 3

// diskFree reports the bytes available on the filesystem of the staging
// directory; ok is false when the platform cannot tell. It is a seam for
// tests, which cannot fill a real disk.
var diskFree = func(s *transferlocal.ChunkStaging) (int64, bool) { return s.FreeBytes() }

// downloadJob is the state of one single-file download: the whole-stream first
// attempt (download.go) and, after a link drop, the chunked resumable loop
// (this file). It lives for one Download call; everything that outlives the
// call is in the local staging directory and the Engine's link profile. The
// structure mirrors uploadJob; the parts live in a local staging directory,
// the remote file is read with ReadRange and the assembly is a local pass.
type downloadJob struct {
	jobReport
	ctx        context.Context
	root       *transferlocal.Root
	remote     string
	local      string
	sum        [32]byte // SHA-256 of the remote file taken before the transfer
	overwrite  bool
	mtime      int64 // whole-second remote mtime the staging key was derived from
	mtimeKnown bool

	chunkOK     bool // chunked mode may be used for this job
	usedChunk   bool // chunked mode was entered
	key         string
	stage       *transferlocal.ChunkStaging // the job's own keyed staging; nil until adopted or created
	covered     int64
	needSync    bool // the staging must be opened and listed again before the next part
	destChecked bool
	diskChecked bool
	restarted   bool
	announced   bool
	streamed    bool // a whole-stream attempt was made
	usedProfile bool // the job consulted the link profile
}

// run executes the job: preflight, then attempts until the file is published
// or the job fails, then the end-of-job bookkeeping.
func (j *downloadJob) run() (Result, error) {
	var res Result
	err := j.preflight()
	if err == nil {
		res, err = j.loop()
	}
	return j.finish(res, err)
}

// preflight prepares the chunked mode of a chunk-capable target: for a file
// worth chunking it reads the remote modification time to derive the staging
// key, collects stale local staging of the destination's directory (its
// failure is ignored) and looks at the staging directory of this very
// transfer. A directory that already holds valid parts forces chunked mode; a
// foreign object at the staging name disables it.
func (j *downloadJob) preflight() error {
	c := j.e.chunk
	if c == nil || !c.ChunkCaps().Download() {
		return nil
	}
	if j.size >= minChunkedFile {
		st, ok, err := j.statSource()
		if err != nil {
			return err
		}
		if ok {
			if st.Size != j.size {
				return transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
			}
			j.mtime, j.mtimeKnown = st.MTime, true
			j.key = transferremote.StagingKey(j.e.target, j.remote, j.local,
				strconv.FormatInt(j.size, 10), strconv.FormatInt(j.mtime, 10))
		}
	}
	_ = j.root.CollectStaleChunkStaging(j.local, j.key)
	if j.ctx.Err() != nil {
		return cancelled()
	}
	if !j.mtimeKnown {
		return nil
	}
	j.chunkOK = true
	j.usedProfile = true
	j.needSync = true
	return j.lookup()
}

// statSource reads size and modification time of the remote file. A target
// that cannot answer simply has no chunked mode for this call: ok is false and
// the whole stream goes on as before. Only a cancelled context is an error.
func (j *downloadJob) statSource() (st transferremote.SourceStat, ok bool, err error) {
	for try := 0; try < statSourceTries; try++ {
		start := j.e.now()
		got, serr := j.e.chunk.StatSource(j.ctx, j.remote)
		if serr == nil {
			j.e.profile.ConnectionSetup(j.e.now().Sub(start))
			return got, true, nil
		}
		if j.ctx.Err() != nil {
			return transferremote.SourceStat{}, false, cancelled()
		}
		if !transferremote.IsLinkFailure(serr) {
			break
		}
	}
	return transferremote.SourceStat{}, false, nil
}

// lookup opens the staging directory of this transfer, if there is one.
func (j *downloadJob) lookup() error {
	stage, state, err := j.root.OpenChunkStaging(j.local, j.key, j.sum, j.overwrite, false)
	if err != nil {
		return classify(j.ctx, err)
	}
	switch state {
	case transferlocal.ChunkForeign:
		j.chunkOK = false
	case transferlocal.ChunkReused:
		j.stage = stage
		overflow, err := j.takeListing()
		switch {
		case errors.Is(err, transferlocal.ErrChunkStagingGone):
			j.stage = nil
			return nil
		case err != nil:
			return classify(j.ctx, err)
		case overflow:
			if stage.Remove() == nil {
				j.stage = nil
			}
			return nil
		}
		if len(j.parts) > 0 {
			var largest int64
			for _, p := range j.parts {
				largest = max(largest, p.Len)
			}
			j.e.profile.ForceChunked(largest)
			j.needSync = false
		}
	}
	return nil
}

// loop runs attempts until the file is published or fails. The first attempt
// is the whole stream; after a link drop the profile decides between another
// stream and chunked mode, and eight attempts without progress end the job as
// link_unstable.
func (j *downloadJob) loop() (Result, error) {
	for {
		if j.chunkOK {
			if j.ctx.Err() != nil {
				return Result{}, cancelled()
			}
			if j.e.profile.GiveUp() {
				return Result{}, transfercore.Fail(transfercore.ClassLinkUnstable, transfercore.MsgLinkUnstable)
			}
		}
		if chunked, planned := j.nextStep(j.chunkOK, j.covered); chunked {
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

// chunkStep makes one step of the chunked loop. final reports that res and err
// are the outcome of the job; otherwise the loop continues (a part was stored,
// or an attempt ended in a drop that the profile has been told about).
func (j *downloadJob) chunkStep(planned int64) (res Result, final bool, err error) {
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
	if j.stage == nil {
		return Result{}, true, transfercore.Fail(transfercore.ClassInternal, msgFailed)
	}
	if !j.destChecked {
		if err := j.stage.CheckDestination(); err != nil {
			return Result{}, true, classify(j.ctx, err)
		}
		j.destChecked = true
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
		if j.diskShort() {
			return Result{}, true, transfercore.Fail(transfercore.ClassLimit, msgLocalDiskShort)
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
	return j.fetchPart(rg, planned)
}

// sync makes the staging directory exist and rebuilds the coverage from its
// listing. ok is false when the step has to be tried again (the directory
// vanished, or a corrupt one was removed): the loop then goes on.
func (j *downloadJob) sync() (ok bool, err error) {
	stage, state, err := j.root.OpenChunkStaging(j.local, j.key, j.sum, j.overwrite, true)
	if err != nil {
		return false, classify(j.ctx, err)
	}
	if state == transferlocal.ChunkForeign {
		j.stage = nil
		return j.foreignStaging()
	}
	j.stage = stage
	if state == transferlocal.ChunkCreated && len(j.parts) > 0 {
		// The staging vanished behind the job's back: start again from zero.
		j.parts, j.covered = nil, 0
		j.refreshCounts()
	}
	overflow, err := j.takeListing()
	switch {
	case errors.Is(err, transferlocal.ErrChunkStagingGone):
		j.noteDrop(0, 0)
		return false, nil
	case err != nil:
		return false, classify(j.ctx, err)
	case overflow:
		// A corrupt staging is removed and the job restarts from zero once.
		if j.restarted {
			return false, transfercore.Fail(transfercore.ClassInternal, msgFailed)
		}
		j.restarted = true
		j.parts, j.covered = nil, 0
		j.refreshCounts()
		if err := stage.Remove(); err != nil {
			return false, classify(j.ctx, err)
		}
		j.stage = nil
		return false, nil
	}
	j.needSync = false
	return true, nil
}

// foreignStaging handles a foreign object at the staging name, which is never
// adopted, written to or removed. Before any stream was tried the job falls
// back to the whole stream; after a link failure it fails.
func (j *downloadJob) foreignStaging() (bool, error) {
	if !j.streamed && len(j.parts) == 0 {
		j.chunkOK = false
		return false, nil
	}
	return false, transfercore.Fail(transfercore.ClassRefusedPath, msgStagingForeign)
}

// takeListing adopts the local listing of the staging directory: the accepted
// parts become the coverage; ignored entries were removed by the listing.
func (j *downloadJob) takeListing() (overflow bool, err error) {
	parts, overflow, err := j.stage.ListParts(j.size, transferremote.MaxListedParts(j.e.limits))
	if err != nil || overflow {
		return overflow, err
	}
	j.parts = parts
	j.covered = 0
	for _, p := range parts {
		j.covered += p.Len
	}
	j.refreshCounts()
	return false, nil
}

// diskShort reports whether the destination's filesystem lacks the room for
// the rest of the parts plus the assembled file: (size - bytes in valid parts)
// + size. An unknown answer skips the check.
func (j *downloadJob) diskShort() bool {
	if j.stage == nil {
		return false
	}
	avail, ok := diskFree(j.stage)
	return ok && avail < spaceNeeded(j.size, j.covered)
}

// recheckSource looks at the remote file again: another size or modification
// time than the staging key was derived from is integrity. ok is false when
// the session dropped (the profile has been told) and the step is tried again.
func (j *downloadJob) recheckSource() (ok bool, err error) {
	start := j.e.now()
	st, serr := j.e.chunk.StatSource(j.ctx, j.remote)
	life := j.e.now().Sub(start)
	if serr != nil {
		switch {
		case j.ctx.Err() != nil:
			return false, cancelled()
		case transferremote.IsLinkFailure(serr):
			j.noteDrop(0, life)
			return false, nil
		}
		return false, classify(j.ctx, serr)
	}
	j.e.profile.ConnectionSetup(life)
	if st.Size != j.size || st.MTime != j.mtime {
		return false, transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}
	return true, nil
}

// partSink receives the bytes of one part from the remote read. It records the
// first local write failure, so a full local disk is not mistaken for a link
// failure of the session that happened to be copying into it.
type partSink struct {
	w *transferlocal.PartWriter

	mu  sync.Mutex
	err error
}

func (p *partSink) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	if err != nil {
		p.mu.Lock()
		if p.err == nil {
			p.err = err
		}
		p.mu.Unlock()
	}
	return n, err
}

func (p *partSink) failure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// fetchPart reads one range of the remote file into a part of the staging
// directory. Before every part the remote file is looked at again.
func (j *downloadJob) fetchPart(rg transferlink.Range, planned int64) (Result, bool, error) {
	if len(j.parts) >= transferremote.MaxListedParts(j.e.limits) {
		return Result{}, true, transfercore.Fail(transfercore.ClassLimit, msgLimitExceeded)
	}
	ok, err := j.recheckSource()
	if err != nil {
		return Result{}, true, err
	}
	if !ok {
		return Result{}, false, nil
	}
	j.beginAttempt(ModeChunked)
	j.setChunkLen(planned)
	w, err := j.stage.CreatePart(rg)
	if err != nil {
		if errors.Is(err, transferlocal.ErrChunkStagingGone) {
			j.needSync = true
			j.noteDrop(0, 0)
			return Result{}, false, nil
		}
		return Result{}, true, classify(j.ctx, err)
	}
	sink := &partSink{w: w}
	start := j.e.now()
	wd, wctx := j.e.stall.start(j.ctx)
	got, err := j.e.chunk.ReadRange(wctx, j.remote, rg, planned, j.size, &stallWriter{w: sink, wd: wd})
	err = j.stallError(err, wd.stop())
	elapsed := j.e.now().Sub(start)
	if err != nil {
		w.Abort()
		return j.sessionFailed(err, sink, got, elapsed)
	}
	if err := w.Commit(); err != nil {
		if transfercore.ClassOf(err) == transfercore.ClassIntegrity {
			return Result{}, true, err
		}
		return j.localWriteFailed()
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

// sessionFailed handles the error of a range read. A local write failure comes
// first; then a link failure is a drop (the profile is told, the attempt is
// repeated), anything else, including a source that no longer has the bytes,
// ends the job.
func (j *downloadJob) sessionFailed(err error, sink *partSink, got int64, life time.Duration) (Result, bool, error) {
	if j.ctx.Err() != nil {
		return Result{}, true, cancelled()
	}
	if sink.failure() != nil {
		return j.localWriteFailed()
	}
	if transferremote.IsLinkFailure(err) {
		j.noteDrop(got, life)
		return Result{}, false, nil
	}
	return Result{}, true, classify(j.ctx, err)
}

// localWriteFailed ends the job after a failed local write: limit when the
// disk check says the disk is full, a fixed internal failure otherwise.
func (j *downloadJob) localWriteFailed() (Result, bool, error) {
	if j.diskShort() {
		return Result{}, true, transfercore.Fail(transfercore.ClassLimit, msgLocalDiskShort)
	}
	return Result{}, true, transfercore.Fail(transfercore.ClassInternal, msgStagedWrite)
}

// assemble looks at the remote file once more, concatenates the parts into one
// local file while hashing, compares the digest with the remote pre-hash and
// publishes. A drop keeps the staging and tries again; parts that went missing
// or changed are listed again and fetched again.
func (j *downloadJob) assemble() (Result, bool, error) {
	j.beginAttempt(ModeChunked)
	j.emit(transfercore.PhaseVerify, j.covered)
	ok, err := j.recheckSource()
	if err != nil {
		return Result{}, true, err
	}
	if !ok {
		return Result{}, false, nil
	}
	if err := transferlink.ValidateTiling(j.size, j.parts); err != nil {
		return Result{}, true, transfercore.Fail(transfercore.ClassInternal, msgFailed)
	}
	digest, err := j.stage.Assemble(j.ctx, j.parts, j.size)
	switch {
	case err == nil:
	case j.ctx.Err() != nil:
		return Result{}, true, cancelled()
	case errors.Is(err, transferlocal.ErrChunkPartInvalid), errors.Is(err, transferlocal.ErrChunkStagingGone):
		j.needSync = true
		j.noteDrop(0, 0)
		return Result{}, false, nil
	default:
		return j.localWriteFailed()
	}
	if digest != j.sum {
		return Result{}, true, transfercore.Fail(transfercore.ClassIntegrity, msgSourceChanged)
	}
	j.emit(transfercore.PhasePublish, j.size)
	if err := j.stage.Publish(); err != nil {
		return Result{}, true, classify(j.ctx, err)
	}
	j.stage = nil
	j.emit(transfercore.PhaseCleanup, j.size)
	return Result{Kind: KindFile, Files: 1, Bytes: j.size, SHA256: hex.EncodeToString(j.sum[:])}, true, nil
}

// noteStreamError reports whether err is a link failure of the stream and, if
// chunked mode is possible, feeds the drop to the link profile: bytes is what
// the stream wrote locally, the lifetime runs from since to now.
func (j *downloadJob) noteStreamError(err error, bytes int64, since time.Time) bool {
	if j.ctx.Err() != nil || !transferremote.IsLinkFailure(err) {
		return false
	}
	if j.chunkOK {
		j.noteDrop(bytes, j.e.now().Sub(since))
	}
	return true
}

// finish ends the job: the link profile learns that the transfer ended, the
// job's own staging is removed unless the job is resumable, and the
// chunked-mode fields are filled in when the job left the plain stream.
func (j *downloadJob) finish(res Result, err error) (Result, error) {
	j.endProfile(j.usedProfile, err)
	j.cleanupStaging(err)
	return j.decorate(res, err, j.usedChunk, j.covered)
}

// cleanupStaging removes the job's own staging directory unless the job ended
// in link_unstable: that staging stays for the next call to resume. A failed
// removal never changes the outcome (staging idle for a day is collected by a
// later transfer into the same directory).
func (j *downloadJob) cleanupStaging(err error) {
	if j.stage == nil {
		return
	}
	if err != nil && transfercore.ClassOf(err) == transfercore.ClassLinkUnstable {
		return
	}
	_ = j.stage.Remove()
}
