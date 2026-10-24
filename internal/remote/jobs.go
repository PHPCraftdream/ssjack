package remote

import (
	"context"
	"errors"
	"io"
	"sort"
	"sync"
	"time"

	"storagehost/internal/broker"
	"storagehost/internal/wire"
)

const (
	outputLimit = 256 * 1024
	chunkLimit  = 32 * 1024
	maxJobs     = 64
	maxActive   = 4
)

type Runner func(context.Context, string, string, io.Writer, io.Writer) (int, error)

type StartInput struct {
	Target         string `json:"target" jsonschema:"Name of a preconfigured SSH target"`
	Command        string `json:"command" jsonschema:"Noninteractive remote shell command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"Timeout from 1 to 3600 seconds; defaults to 600"`
}

type StartOutput struct {
	JobID string `json:"job_id"`
}

type ReadInput struct {
	JobID        string `json:"job_id"`
	StdoutOffset int64  `json:"stdout_offset,omitempty"`
	StderrOffset int64  `json:"stderr_offset,omitempty"`
}

type JobInput struct {
	JobID string `json:"job_id"`
}

type ReadOutput struct {
	JobID        string `json:"job_id"`
	Stdout       []byte `json:"stdout"`
	Stderr       []byte `json:"stderr"`
	StdoutOffset int64  `json:"stdout_offset"`
	StderrOffset int64  `json:"stderr_offset"`
	StdoutLost   bool   `json:"stdout_lost"`
	StderrLost   bool   `json:"stderr_lost"`
	StdoutMore   bool   `json:"stdout_more"`
	StderrMore   bool   `json:"stderr_more"`
	Done         bool   `json:"done"`
	ExitCode     int    `json:"exit_code"`
	Error        string `json:"error,omitempty"`
}

type TargetsOutput struct {
	Targets []string `json:"targets"`
}

type CancelOutput struct {
	Cancelled bool `json:"cancelled"`
}

type capture struct {
	mu    sync.Mutex
	data  []byte
	total int64
}

func (b *capture) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(data)
	b.total += int64(n)
	if n >= outputLimit {
		b.data = append(b.data[:0], data[n-outputLimit:]...)
	} else {
		if excess := len(b.data) + n - outputLimit; excess > 0 {
			copy(b.data, b.data[excess:])
			b.data = b.data[:len(b.data)-excess]
		}
		b.data = append(b.data, data...)
	}
	return n, nil
}

func (b *capture) read(offset int64) ([]byte, int64, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if offset < 0 || offset > b.total {
		return nil, offset, false, errors.New("invalid output offset")
	}
	start := b.total - int64(len(b.data))
	lost := offset < start
	if lost {
		offset = start
	}
	index := int(offset - start)
	end := min(index+chunkLimit, len(b.data))
	return append([]byte{}, b.data[index:end]...), offset + int64(end-index), lost, nil
}

func (b *capture) more(offset int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return offset < b.total
}

type job struct {
	stdout capture
	stderr capture
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	exit   int
	err    string
}

type Manager struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	runner  Runner
	targets map[string]bool
	jobs    map[string]*job
	order   []string
	active  int
	closed  bool
	wg      sync.WaitGroup
	bind    sync.Once
}

func NewManager(parent context.Context, targets []string, runner Runner) *Manager {
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{ctx: ctx, cancel: cancel, runner: runner, targets: make(map[string]bool), jobs: make(map[string]*job)}
	for _, target := range targets {
		m.targets[target] = true
	}
	return m
}

func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *Manager) Start(input StartInput) (StartOutput, error) {
	if input.Command == "" || len(input.Command) > 16*1024 || input.TimeoutSeconds < 0 || input.TimeoutSeconds > 3600 {
		return StartOutput{}, errors.New("invalid command or timeout")
	}
	if input.TimeoutSeconds == 0 {
		input.TimeoutSeconds = 600
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return StartOutput{}, errors.New("session closed")
	}
	if !m.targets[input.Target] {
		return StartOutput{}, errors.New("target is not allowed")
	}
	if m.active >= maxActive {
		return StartOutput{}, errors.New("concurrent operation limit reached")
	}
	if len(m.jobs) >= maxJobs {
		for i, id := range m.order {
			select {
			case <-m.jobs[id].done:
				delete(m.jobs, id)
				m.order = append(m.order[:i], m.order[i+1:]...)
			default:
				continue
			}
			break
		}
		if len(m.jobs) >= maxJobs {
			return StartOutput{}, errors.New("retained operation limit reached")
		}
	}
	id, err := wire.RandomToken()
	if err != nil {
		return StartOutput{}, err
	}
	ctx, cancel := context.WithTimeout(m.ctx, time.Duration(input.TimeoutSeconds)*time.Second)
	j := &job{cancel: cancel, done: make(chan struct{}), exit: -1}
	m.jobs[id] = j
	m.order = append(m.order, id)
	m.active++
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer cancel()
		exit, err := m.runner(ctx, input.Target, input.Command, &j.stdout, &j.stderr)
		j.mu.Lock()
		j.exit = exit
		if err != nil {
			j.err = err.Error()
		}
		j.mu.Unlock()
		m.mu.Lock()
		m.active--
		close(j.done)
		m.mu.Unlock()
	}()
	return StartOutput{JobID: id}, nil
}

func (m *Manager) get(id string) (*job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j := m.jobs[id]
	if j == nil {
		return nil, errors.New("unknown operation")
	}
	return j, nil
}

func (m *Manager) Read(input ReadInput) (ReadOutput, error) {
	j, err := m.get(input.JobID)
	if err != nil {
		return ReadOutput{}, err
	}
	out := ReadOutput{JobID: input.JobID, ExitCode: -1}
	// Check done before buffers so a completed response cannot miss trailing output.
	select {
	case <-j.done:
		out.Done = true
	default:
	}
	out.Stdout, out.StdoutOffset, out.StdoutLost, err = j.stdout.read(input.StdoutOffset)
	if err != nil {
		return ReadOutput{}, err
	}
	out.Stderr, out.StderrOffset, out.StderrLost, err = j.stderr.read(input.StderrOffset)
	if err != nil {
		return ReadOutput{}, err
	}
	out.StdoutMore = j.stdout.more(out.StdoutOffset)
	out.StderrMore = j.stderr.more(out.StderrOffset)
	if out.Done {
		j.mu.Lock()
		out.ExitCode, out.Error = j.exit, j.err
		j.mu.Unlock()
	}
	return out, nil
}

func (m *Manager) Cancel(id string) (CancelOutput, error) {
	j, err := m.get(id)
	if err != nil {
		return CancelOutput{}, err
	}
	j.cancel()
	return CancelOutput{Cancelled: true}, nil
}

func decode(data string, value any) error {
	if wire.Decode(data, value) != nil {
		return errors.New("invalid operation arguments")
	}
	return nil
}

func (m *Manager) Handle(ctx context.Context, req wire.Request) wire.Reply {
	m.bind.Do(func() { context.AfterFunc(ctx, m.cancel) })
	switch req.Operation {
	case "targets":
		var targets []string
		for name := range m.targets {
			targets = append(targets, name)
		}
		sort.Strings(targets)
		return broker.Result(TargetsOutput{Targets: targets}, nil)
	case "start":
		var input StartInput
		if err := decode(req.Data, &input); err != nil {
			return broker.Result(nil, err)
		}
		out, err := m.Start(input)
		return broker.Result(out, err)
	case "read":
		var input ReadInput
		if err := decode(req.Data, &input); err != nil {
			return broker.Result(nil, err)
		}
		out, err := m.Read(input)
		return broker.Result(out, err)
	case "cancel":
		var input JobInput
		if err := decode(req.Data, &input); err != nil {
			return broker.Result(nil, err)
		}
		out, err := m.Cancel(input.JobID)
		return broker.Result(out, err)
	default:
		return broker.Result(nil, errors.New("operation is not allowed"))
	}
}
