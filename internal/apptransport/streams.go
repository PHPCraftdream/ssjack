package apptransport

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const ChunkSize = 16 * 1024

const (
	maxActive   = 4
	maxRetained = 32
)

type StartInput struct {
	Command   string `json:"command"`
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

type StartOutput struct {
	JobID string `json:"job_id"`
}

type InputInput struct {
	JobID string `json:"job_id"`
	Data  string `json:"data,omitempty"`
	EOF   bool   `json:"eof,omitempty"`
}

type InputOutput struct {
	Accepted bool `json:"accepted"`
}

type JobInput struct {
	JobID string `json:"job_id"`
}

type ReadOutput struct {
	Stream   string `json:"stream,omitempty"`
	Data     string `json:"data,omitempty"`
	Pending  bool   `json:"pending,omitempty"`
	Done     bool   `json:"done"`
	ExitCode int    `json:"exit_code"`
	TimedOut bool   `json:"timed_out,omitempty"`
	Error    string `json:"error,omitempty"`
}

type CancelOutput struct {
	Cancelled bool `json:"cancelled"`
}

type event struct {
	stream string
	data   []byte
}

type streamJob struct {
	ctx      context.Context
	cancel   context.CancelFunc
	input    chan []byte
	output   chan event
	done     chan struct{}
	inputMu  sync.Mutex
	eof      bool
	exit     int
	err      string
	timedOut bool
	drained  atomic.Bool
}

type streams struct {
	ctx     context.Context
	cancel  context.CancelFunc
	profile string
	runner  remote.StreamRunner
	mu      sync.Mutex
	jobs    map[string]*streamJob
	order   []string
	wg      sync.WaitGroup
	closed  bool
}

func newStreams(parent context.Context, profile string, runner remote.StreamRunner) *streams {
	ctx, cancel := context.WithCancel(parent)
	return &streams{ctx: ctx, cancel: cancel, profile: profile, runner: runner, jobs: make(map[string]*streamJob)}
}

func (s *streams) close() {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *streams) start(input StartInput) (StartOutput, error) {
	if input.Command == "" || len(input.Command) > 64*1024 || strings.IndexByte(input.Command, 0) >= 0 || input.TimeoutMS < 0 || input.TimeoutMS > 3600000 {
		return StartOutput{}, errors.New("invalid transport command or deadline")
	}
	if input.TimeoutMS == 0 {
		input.TimeoutMS = 600000
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return StartOutput{}, errors.New("application transport is closed")
	}
	active := 0
	for _, j := range s.jobs {
		select {
		case <-j.done:
		default:
			active++
		}
	}
	if active >= maxActive {
		return StartOutput{}, errors.New("application transport concurrency limit reached")
	}
	if len(s.jobs) >= maxRetained {
		for i, id := range s.order {
			if s.jobs[id].drained.Load() {
				delete(s.jobs, id)
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
		if len(s.jobs) >= maxRetained {
			return StartOutput{}, errors.New("application transport retention limit reached")
		}
	}
	id, err := wire.RandomToken()
	if err != nil {
		return StartOutput{}, err
	}
	ctx, cancel := context.WithTimeout(s.ctx, time.Duration(input.TimeoutMS)*time.Millisecond)
	j := &streamJob{ctx: ctx, cancel: cancel, input: make(chan []byte, 4), output: make(chan event, 16), done: make(chan struct{}), exit: -1}
	s.jobs[id] = j
	s.order = append(s.order, id)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		exit, runErr := s.runner(ctx, s.profile, input.Command, &jobInputReader{job: j}, &eventWriter{job: j, stream: "stdout"}, &eventWriter{job: j, stream: "stderr"})
		j.exit = exit
		if runErr != nil {
			j.err = "remote transport operation failed"
		}
		if ctx.Err() != nil {
			j.err = ctx.Err().Error()
			j.timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		}
		close(j.done)
		close(j.output)
	}()
	return StartOutput{JobID: id}, nil
}

func (s *streams) get(id string) (*streamJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[id]
	if j == nil {
		return nil, errors.New("unknown application transport operation")
	}
	return j, nil
}

func (s *streams) write(input InputInput) (InputOutput, error) {
	if len(input.Data) > base64.StdEncoding.EncodedLen(ChunkSize) || (input.EOF && input.Data != "") {
		return InputOutput{}, errors.New("invalid transport input chunk")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(input.Data)
	if err != nil || len(data) > ChunkSize {
		return InputOutput{}, errors.New("invalid base64 transport input")
	}
	j, err := s.get(input.JobID)
	if err != nil {
		return InputOutput{}, err
	}
	j.inputMu.Lock()
	defer j.inputMu.Unlock()
	select {
	case <-j.done:
		if input.EOF {
			return InputOutput{Accepted: true}, nil
		}
		return InputOutput{}, errors.New("transport operation has finished")
	default:
	}
	if j.eof {
		if input.EOF {
			return InputOutput{Accepted: true}, nil
		}
		return InputOutput{}, errors.New("transport input is closed")
	}
	if len(data) == 0 && !input.EOF {
		return InputOutput{Accepted: true}, nil
	}
	select {
	case <-j.ctx.Done():
		return InputOutput{}, errors.New("transport operation is cancelled")
	case j.input <- data:
		j.eof = input.EOF
		return InputOutput{Accepted: true}, nil
	default:
		return InputOutput{Accepted: false}, nil
	}
}

func (s *streams) read(ctx context.Context, input JobInput) (ReadOutput, error) {
	j, err := s.get(input.JobID)
	if err != nil {
		return ReadOutput{}, err
	}
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ReadOutput{}, ctx.Err()
	case item, ok := <-j.output:
		if ok {
			return ReadOutput{Stream: item.stream, Data: base64.StdEncoding.EncodeToString(item.data), ExitCode: -1}, nil
		}
		j.drained.Store(true)
		return ReadOutput{Done: true, ExitCode: j.exit, Error: j.err, TimedOut: j.timedOut}, nil
	case <-timer.C:
		return ReadOutput{Pending: true, ExitCode: -1}, nil
	}
}

func (s *streams) stop(input JobInput) (CancelOutput, error) {
	j, err := s.get(input.JobID)
	if err != nil {
		return CancelOutput{}, err
	}
	j.cancel()
	return CancelOutput{Cancelled: true}, nil
}

type jobInputReader struct {
	job     *streamJob
	pending []byte
	eof     bool
}

func (r *jobInputReader) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	if err := r.job.ctx.Err(); err != nil {
		return 0, err
	}
	if r.eof {
		return 0, io.EOF
	}
	if len(r.pending) == 0 {
		select {
		case <-r.job.ctx.Done():
			return 0, r.job.ctx.Err()
		case r.pending = <-r.job.input:
			if len(r.pending) == 0 {
				r.eof = true
				return 0, io.EOF
			}
		}
	}
	n := copy(out, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

type eventWriter struct {
	job    *streamJob
	stream string
}

func (w *eventWriter) Write(data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		n := min(len(data), ChunkSize)
		item := event{stream: w.stream, data: append([]byte(nil), data[:n]...)}
		select {
		case <-w.job.ctx.Done():
			return total, w.job.ctx.Err()
		case w.job.output <- item:
			total += n
			data = data[n:]
		}
	}
	return total, nil
}
