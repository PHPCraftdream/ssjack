package transfer

import (
	"context"
	"errors"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const (
	maxActive   = 2
	maxRetained = 64
)

var (
	errNoRoots    = errors.New("no transfer roots are registered; the owner registers one with --transfer-root when starting the keeper")
	errUnknownJob = errors.New("unknown transfer job")
)

type jobState string

const (
	stateRunning   jobState = "running"
	stateDone      jobState = "done"
	stateFailed    jobState = "failed"
	stateCancelled jobState = "cancelled"
)

// statusMessage is the fixed, content-free message for one error class.
func statusMessage(class transfercore.Class) string {
	switch class {
	case transfercore.ClassRefusedPath:
		return "transfer path was refused"
	case transfercore.ClassExists:
		return "transfer destination already exists"
	case transfercore.ClassLimit:
		return "transfer exceeds the configured limits"
	case transfercore.ClassUnsupportedRemote:
		return "remote target is missing required transfer tools"
	case transfercore.ClassIntegrity:
		return "transfer failed verification"
	case transfercore.ClassRemoteFailed:
		return "remote operation failed"
	case transfercore.ClassLinkUnstable:
		return transfercore.MsgLinkUnstable
	case transfercore.ClassCancelled:
		return "transfer was cancelled"
	default:
		return "transfer failed"
	}
}

// kindName maps an engine kind to its status name.
func kindName(kind transferengine.Kind) string {
	switch kind {
	case transferengine.KindFile:
		return "file"
	case transferengine.KindDir:
		return "directory"
	default:
		return ""
	}
}

// chunkReport is the content-free chunked-mode part of a job record: a mode
// name and plain integers, zero while absent.
type chunkReport struct {
	mode           string
	chunkBytes     int64
	chunksDone     int
	chunksTotal    int
	attempts       int
	bytesPerSecond int64
}

// validMode reports whether the engine named a mode the status may carry.
func validMode(mode string) bool {
	return mode == transferengine.ModeStream || mode == transferengine.ModeChunked
}

// chunkReportOf copies the chunked-mode fields of a Progress or Result,
// dropping negative numbers.
func chunkReportOf(mode string, chunkBytes int64, done, total, attempts int, bps int64) chunkReport {
	return chunkReport{
		mode: mode, chunkBytes: max(chunkBytes, 0), chunksDone: max(done, 0), chunksTotal: max(total, 0),
		attempts: max(attempts, 0), bytesPerSecond: max(bps, 0),
	}
}

type job struct {
	id        string
	direction string
	dest      string
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.Mutex
	phase     string
	high      int64 // the largest bytes value published so far; never decreases
	rep       chunkReport
	state     jobState
	result    transferengine.Result
	errClass  transfercore.Class
}

// observe records one engine progress report. Bytes never decrease. The
// chunked-mode fields are replaced only by a report that carries a mode: a
// report without one (a directory, or the preflight of a file) keeps what is
// known.
func (j *job) observe(p transferengine.Progress) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.phase = p.Phase
	j.high = max(j.high, p.Bytes)
	if validMode(p.Mode) {
		j.rep = chunkReportOf(p.Mode, p.ChunkBytes, p.ChunksDone, p.ChunksTotal, p.Attempts, p.BytesPerSecond)
	}
}

// finish records the outcome of the engine call.
//
// Bytes never decrease: the final value is the larger of the verified bytes of
// the result and the bytes already published. A finished directory is the one
// exception: its running figure counts tar framing, so the manifest total of
// its result is authoritative. A result carrying a mode (a file transfer that
// left the plain first stream, also a failed one) replaces the last progress
// report; a plain successful file stream is one attempt in stream mode.
func (j *job) finish(result transferengine.Result, state jobState, class transfercore.Class) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.result, j.state, j.errClass = result, state, class
	if state == stateDone && result.Kind == transferengine.KindDir {
		j.high = result.Bytes
		j.rep = chunkReport{}
		return
	}
	j.high = max(j.high, result.Bytes)
	switch {
	case validMode(result.Mode):
		j.rep = chunkReportOf(result.Mode, result.ChunkBytes, result.ChunksDone, result.ChunksTotal, result.Attempts, result.BytesPerSecond)
	case state == stateDone && j.rep.mode == "":
		j.rep = chunkReport{mode: transferengine.ModeStream, attempts: 1}
	}
}

// engineSlot holds the lazily built engine of one target.
type engineSlot struct {
	mu     sync.Mutex
	engine Engine
}

// Manager runs bounded file-transfer jobs over approved roots and targets.
type Manager struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	roots    *transferlocal.Roots
	hasRoots bool
	targets  map[string]bool
	limits   transfercore.Limits
	build    func(string) (Engine, error)
	engines  map[string]*engineSlot
	jobs     map[string]*job
	dests    map[string]string
	order    []string
	active   int
	closed   bool
	wg       sync.WaitGroup
	bind     sync.Once
}

// NewManager roots transfers in the owner-registered roots and approved
// targets; build returns the engine for one target name. The manager calls it
// once per target (a failed call is retried by the next job) and shares the
// engine, with its link profile, between all jobs of that target.
func NewManager(roots []*transferlocal.Root, targets []string, limits transfercore.Limits, build func(string) (Engine, error)) (*Manager, error) {
	if err := limits.Validate(); err != nil {
		return nil, errors.New("transfer limits are invalid")
	}
	if build == nil {
		return nil, errors.New("transfer engine is not configured")
	}
	collection := transferlocal.NewRoots()
	for _, root := range roots {
		if err := collection.Add(root); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		ctx: ctx, cancel: cancel, roots: collection, hasRoots: len(roots) > 0,
		targets: make(map[string]bool), limits: limits, build: build,
		engines: make(map[string]*engineSlot),
		jobs:    make(map[string]*job), dests: make(map[string]string),
	}
	for _, target := range targets {
		if target != "" {
			m.targets[target] = true
		}
	}
	return m, nil
}

// Close refuses new jobs, cancels running ones and waits for them.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *Manager) start(input StartInput, download bool) (StartOutput, error) {
	if input.Target == "" || input.Local == "" || input.Remote == "" {
		return StartOutput{}, errors.New("invalid transfer arguments")
	}
	if input.Overwrite && !input.Confirm {
		return StartOutput{}, errors.New("overwrite requires confirm=true")
	}
	m.mu.Lock()
	if m.closed || m.ctx.Err() != nil {
		m.mu.Unlock()
		return StartOutput{}, errors.New("session closed")
	}
	if !m.hasRoots {
		m.mu.Unlock()
		return StartOutput{}, errNoRoots
	}
	if !m.targets[input.Target] {
		m.mu.Unlock()
		return StartOutput{}, errors.New("target is not allowed")
	}
	root, err := m.roots.Select(input.Root)
	if err != nil {
		m.mu.Unlock()
		return StartOutput{}, err
	}
	dest := "upload\x00" + input.Target + "\x00" + input.Remote
	if download {
		dest = "download\x00" + root.Dir() + "\x00" + input.Local
	}
	if _, busy := m.dests[dest]; busy {
		m.mu.Unlock()
		return StartOutput{}, errors.New("another transfer is using this destination")
	}
	if m.active >= maxActive {
		m.mu.Unlock()
		return StartOutput{}, errors.New("concurrent transfer limit reached")
	}
	if len(m.jobs) >= maxRetained && !m.evictOldestFinishedLocked() {
		m.mu.Unlock()
		return StartOutput{}, errors.New("retained transfer limit reached")
	}
	id, err := wire.RandomToken()
	if err != nil {
		m.mu.Unlock()
		return StartOutput{}, err
	}
	ctx, cancel := context.WithCancel(m.ctx)
	j := &job{id: id, cancel: cancel, done: make(chan struct{}), state: stateRunning, dest: dest, direction: "upload"}
	if download {
		j.direction = "download"
	}
	m.jobs[id] = j
	m.order = append(m.order, id)
	m.dests[dest] = id
	m.active++
	m.wg.Add(1)
	go m.run(ctx, j, root, input, download)
	m.mu.Unlock()
	return StartOutput{JobID: id}, nil
}

// evictOldestFinishedLocked removes the oldest finished job, if any.
func (m *Manager) evictOldestFinishedLocked() bool {
	for i, id := range m.order {
		j := m.jobs[id]
		select {
		case <-j.done:
			delete(m.jobs, id)
			m.order = append(m.order[:i], m.order[i+1:]...)
			return true
		default:
		}
	}
	return false
}

// engineFor returns the one engine of a target, building it on first use. Every
// job of the target shares it, so what the engine learns about the link carries
// over from job to job. Concurrent first uses build once; a failed build is not
// cached, and the next job builds again.
func (m *Manager) engineFor(target string) (Engine, error) {
	m.mu.Lock()
	slot := m.engines[target]
	if slot == nil {
		slot = &engineSlot{}
		m.engines[target] = slot
	}
	m.mu.Unlock()
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.engine != nil {
		return slot.engine, nil
	}
	engine, err := m.build(target)
	if err != nil {
		return nil, err
	}
	if engine == nil {
		return nil, errors.New("transfer engine is not configured")
	}
	slot.engine = engine
	return engine, nil
}

func (m *Manager) run(ctx context.Context, j *job, root *transferlocal.Root, input StartInput, download bool) {
	defer m.wg.Done()
	defer j.cancel()
	var result transferengine.Result
	engine, err := m.engineFor(input.Target)
	if err == nil {
		if download {
			result, err = engine.Download(ctx, root, input.Remote, input.Local, input.Overwrite, j.observe)
		} else {
			result, err = engine.Upload(ctx, root, input.Local, input.Remote, input.Overwrite, j.observe)
		}
	}
	var class transfercore.Class
	state := stateFailed
	if err == nil {
		state = stateDone
	} else {
		class = transfercore.ClassOf(err)
		if class == transfercore.ClassCancelled {
			state = stateCancelled
		}
	}
	m.mu.Lock()
	m.active--
	delete(m.dests, j.dest)
	m.mu.Unlock()
	j.finish(result, state, class)
	close(j.done)
}

func (m *Manager) status(id string) (StatusOutput, error) {
	m.mu.Lock()
	j := m.jobs[id]
	m.mu.Unlock()
	if j == nil {
		return StatusOutput{}, errUnknownJob
	}
	out := StatusOutput{JobID: j.id, State: string(stateRunning), Direction: j.direction}
	j.mu.Lock()
	defer j.mu.Unlock()
	select {
	case <-j.done:
		out.State = string(j.state)
		out.Kind = kindName(j.result.Kind)
		out.Files, out.Dirs, out.SHA256 = j.result.Files, j.result.Dirs, j.result.SHA256
		out.ManifestSHA256 = j.result.ManifestSHA256
		if j.state != stateDone {
			out.ErrorClass = string(j.errClass)
			out.Message = statusMessage(j.errClass)
		}
	default:
		out.Phase = j.phase
	}
	out.Bytes = j.high
	out.Mode, out.ChunkBytes = j.rep.mode, j.rep.chunkBytes
	out.ChunksDone, out.ChunksTotal = j.rep.chunksDone, j.rep.chunksTotal
	out.Attempts, out.BytesPerSecond = j.rep.attempts, j.rep.bytesPerSecond
	return out, nil
}

func (m *Manager) cancelJob(id string) (CancelOutput, error) {
	m.mu.Lock()
	j := m.jobs[id]
	m.mu.Unlock()
	if j == nil {
		return CancelOutput{}, errUnknownJob
	}
	select {
	case <-j.done:
		return CancelOutput{Cancelled: false}, nil
	default:
		j.cancel()
		return CancelOutput{Cancelled: true}, nil
	}
}
