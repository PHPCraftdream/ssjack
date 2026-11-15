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
	errNoRoots    = errors.New("no transfer roots are registered")
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

type job struct {
	id        string
	direction string
	dest      string
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.Mutex
	phase     string
	bytes     int64
	state     jobState
	result    transferengine.Result
	errClass  transfercore.Class
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
	jobs     map[string]*job
	dests    map[string]string
	order    []string
	active   int
	closed   bool
	wg       sync.WaitGroup
	bind     sync.Once
}

// NewManager roots transfers in the owner-registered roots and approved
// targets; build returns the engine for one target name.
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
		jobs: make(map[string]*job), dests: make(map[string]string),
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

func (m *Manager) run(ctx context.Context, j *job, root *transferlocal.Root, input StartInput, download bool) {
	defer m.wg.Done()
	defer j.cancel()
	var result transferengine.Result
	engine, err := m.build(input.Target)
	if err == nil {
		progress := func(p transferengine.Progress) {
			j.mu.Lock()
			j.phase, j.bytes = p.Phase, p.Bytes
			j.mu.Unlock()
		}
		if download {
			result, err = engine.Download(ctx, root, input.Remote, input.Local, input.Overwrite, progress)
		} else {
			result, err = engine.Upload(ctx, root, input.Local, input.Remote, input.Overwrite, progress)
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
	j.mu.Lock()
	j.result, j.errClass, j.state = result, class, state
	j.mu.Unlock()
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
	select {
	case <-j.done:
		j.mu.Lock()
		out.State = string(j.state)
		out.Kind = kindName(j.result.Kind)
		out.Files, out.Dirs, out.Bytes, out.SHA256 = j.result.Files, j.result.Dirs, j.result.Bytes, j.result.SHA256
		out.ManifestSHA256 = j.result.ManifestSHA256
		if j.state != stateDone {
			out.ErrorClass = string(j.errClass)
			out.Message = statusMessage(j.errClass)
		}
		j.mu.Unlock()
	default:
		j.mu.Lock()
		out.Phase, out.Bytes = j.phase, j.bytes
		j.mu.Unlock()
	}
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
