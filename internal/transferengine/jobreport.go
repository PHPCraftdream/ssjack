package transferengine

import (
	"math"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transferlink"
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
