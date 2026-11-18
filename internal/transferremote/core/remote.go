// Package core is the runner of the remote half of the ssjack file-transfer
// protocol: it executes fixed command templates over remote.StreamRunner,
// classifies remote exits into content-free errors and holds the probed
// capabilities and the registry of staging paths this job created. The
// operations live in the sibling packages and share one Runner.
package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Runner executes fixed command templates over a StreamRunner.
type Runner struct {
	run    remote.StreamRunner
	target string
	// Limits are the transfer limits every operation validates against.
	Limits  transfercore.Limits
	caps    atomic.Pointer[Caps]
	mu      sync.Mutex
	created map[string]struct{}
}

// NewRunner returns a Runner that runs fixed templates against target via run.
func NewRunner(run remote.StreamRunner, target string, limits transfercore.Limits) *Runner {
	return &Runner{run: run, target: target, Limits: limits, created: map[string]struct{}{}}
}

// Capabilities returns the probe verdict, or the GNU-compatible default
// before Probe ran (unit tests with fake runners never probe).
func (r *Runner) Capabilities() Caps {
	if caps := r.caps.Load(); caps != nil {
		return *caps
	}
	return Caps{
		Hash: HashSha256sum, MvT: true, TarGNU: true, WcNames: true,
		Chunk: ChunkCaps{Own: true, Read: ReadDD, Mtime: MtimeGNU, DF: true},
	}
}

// SetCaps stores the probe verdict.
func (r *Runner) SetCaps(caps Caps) { r.caps.Store(&caps) }

// MarkCreated records a remote path this job created.
func (r *Runner) MarkCreated(path string) {
	r.mu.Lock()
	r.created[path] = struct{}{}
	r.mu.Unlock()
}

// IsCreated reports whether this job created the remote path.
func (r *Runner) IsCreated(path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.created[path]
	return ok
}

// Remote exit codes used by the fixed command templates.
const (
	ExitUnsupported   = 20
	ExitRefusedPath   = 21
	ExitExists        = 22
	ExitIntegrity     = 23
	ExitRemoteFailed  = 24
	ExitRestoreFailed = 25
)

// stderrLimit bounds remote stderr kept in memory; it is never returned.
const stderrLimit = 4096

// Fixed, content-free error messages.
const (
	MsgCancelled      = "transfer was cancelled"
	MsgTransport      = "remote command could not be run"
	MsgUnsupported    = "remote target is missing required transfer tools"
	MsgRefused        = "remote path was refused"
	MsgExists         = "remote destination already exists"
	MsgIntegrity      = "remote data does not match the expected checksums"
	MsgRemoteFailed   = "remote operation failed"
	MsgInternalRunner = "remote runner is not configured"
	MsgInternalLimits = "transfer limits are invalid"
	MsgLimit          = "remote output exceeded its bound"
	MsgNotJobOwned    = "staging path was not created by this job"
)

// Classed builds a content-free error of the given class.
func Classed(class transfercore.Class, message string, exitCode int) *transfercore.Error {
	return &transfercore.Error{Class: class, Message: message, ExitCode: exitCode}
}

// Ready reports whether the runner and its limits are usable.
func (r *Runner) Ready() error {
	if r.run == nil {
		return Classed(transfercore.ClassInternal, MsgInternalRunner, -1)
	}
	if r.Limits.Validate() != nil {
		return Classed(transfercore.ClassInternal, MsgInternalLimits, -1)
	}
	return nil
}

// Execute is the only place StreamRunner is called. Remote stderr is capped
// and discarded. A command that finished successfully is reported as success
// even if the context was cancelled a moment later; only a failed command
// under a cancelled context maps to ClassCancelled, and an oversized stderr
// can no longer turn a classified exit code into a transport failure.
func (r *Runner) Execute(ctx context.Context, command string, stdin io.Reader, stdout io.Writer) error {
	if err := r.Ready(); err != nil {
		return err
	}
	sink := &stderrSink{}
	code, err := r.run(ctx, r.target, command, stdin, stdout, sink)
	if err == nil && code == 0 {
		return nil
	}
	if ctx.Err() != nil {
		return Classed(transfercore.ClassCancelled, MsgCancelled, -1)
	}
	if err != nil {
		return LinkFailure()
	}
	return ClassError(code)
}

// ClassError maps a remote exit code to a class with a fixed message.
func ClassError(code int) *transfercore.Error {
	switch code {
	case ExitUnsupported, 126, 127:
		return Classed(transfercore.ClassUnsupportedRemote, MsgUnsupported, code)
	case ExitRefusedPath:
		return Classed(transfercore.ClassRefusedPath, MsgRefused, code)
	case ExitExists:
		return Classed(transfercore.ClassExists, MsgExists, code)
	case ExitIntegrity:
		return Classed(transfercore.ClassIntegrity, MsgIntegrity, code)
	default:
		return Classed(transfercore.ClassRemoteFailed, MsgRemoteFailed, code)
	}
}

// boundedWriter stops writing once remaining is exhausted.
type boundedWriter struct {
	w         io.Writer
	remaining int64
	overflow  bool
}

var errListingOverflow = errors.New("remote output exceeded its bound")

func (b *boundedWriter) Write(p []byte) (int, error) {
	if b.remaining < int64(len(p)) {
		b.overflow = true
		return 0, errListingOverflow
	}
	n, err := b.w.Write(p)
	if err != nil {
		b.overflow = true
		return n, err
	}
	b.remaining -= int64(n)
	return n, nil
}

// stderrSink keeps the first stderrLimit bytes and silently drops the rest.
// It never fails a write, so a chatty remote tool cannot abort the SSH
// session and hide the real exit code. Nothing is ever read or returned.
type stderrSink struct {
	buf bytes.Buffer
}

func (s *stderrSink) Write(p []byte) (int, error) {
	if room := stderrLimit - s.buf.Len(); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		s.buf.Write(p[:room])
	}
	return len(p), nil
}

// RunListed runs a command that writes a bounded listing to stdout.
func (r *Runner) RunListed(ctx context.Context, command string, bound int64) ([]byte, error) {
	return r.RunFed(ctx, command, nil, bound)
}

// RunFed runs a command with stdin and a bounded stdout, like RunListed.
func (r *Runner) RunFed(ctx context.Context, command string, stdin io.Reader, bound int64) ([]byte, error) {
	var buf bytes.Buffer
	b := &boundedWriter{w: &buf, remaining: bound}
	err := r.Execute(ctx, command, stdin, b)
	if b.overflow {
		return nil, Classed(transfercore.ClassLimit, MsgLimit, 0)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
