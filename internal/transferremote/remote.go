// Package transferremote implements the remote half of the ssjack
// file-transfer protocol: capability probing, staging, file transfer, tree
// listing and verification, tar streaming and atomic publication over
// remote.StreamRunner using fixed command templates.
package transferremote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Remote is the set of remote primitives the transfer engines are built on.
// Later engines compose these primitives; fakes can implement it on any OS.
type Remote interface {
	Probe(ctx context.Context) error
	CreateStaging(ctx context.Context, parent string) (string, error)
	CleanupStaging(ctx context.Context, parent, name string) error
	WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error)
	StatFile(ctx context.Context, path string) (int64, [32]byte, error)
	ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error)
	PreflightTree(ctx context.Context, root string) (transfercore.Manifest, error)
	TarOut(ctx context.Context, root string, dst io.Writer) error
	TarIn(ctx context.Context, root string, src io.Reader) error
	VerifyTree(ctx context.Context, root string, manifest transfercore.Manifest) error
	PublishFile(ctx context.Context, staging, dest string, overwrite bool) error
	PublishDir(ctx context.Context, staging, dest string, overwrite bool) error
}

// remoteRunner executes fixed command templates over a StreamRunner.
type remoteRunner struct {
	run     remote.StreamRunner
	target  string
	limits  transfercore.Limits
	mu      sync.Mutex
	created map[string]struct{}
}

var _ Remote = (*remoteRunner)(nil)

// New returns a Remote that runs fixed templates against target via run.
func New(run remote.StreamRunner, target string, limits transfercore.Limits) Remote {
	return &remoteRunner{run: run, target: target, limits: limits, created: map[string]struct{}{}}
}

// Remote exit codes used by the fixed command templates.
const (
	exitUnsupported   = 20
	exitRefusedPath   = 21
	exitExists        = 22
	exitIntegrity     = 23
	exitRemoteFailed  = 24
	exitRestoreFailed = 25
)

// stderrLimit bounds remote stderr kept in memory; it is never returned.
const stderrLimit = 4096

// Fixed, content-free error messages.
const (
	msgCancelled      = "transfer was cancelled"
	msgTransport      = "remote command could not be run"
	msgUnsupported    = "remote target is missing required transfer tools"
	msgRefused        = "remote path was refused"
	msgExists         = "remote destination already exists"
	msgIntegrity      = "remote data does not match the expected checksums"
	msgRemoteFailed   = "remote operation failed"
	msgInternalRunner = "remote runner is not configured"
	msgInternalLimits = "transfer limits are invalid"
	msgLimit          = "remote output exceeded its bound"
	msgNotJobOwned    = "staging path was not created by this job"
)

func classed(class transfercore.Class, message string, exitCode int) *transfercore.Error {
	return &transfercore.Error{Class: class, Message: message, ExitCode: exitCode}
}

func (r *remoteRunner) ready() error {
	if r.run == nil {
		return classed(transfercore.ClassInternal, msgInternalRunner, -1)
	}
	if r.limits.Validate() != nil {
		return classed(transfercore.ClassInternal, msgInternalLimits, -1)
	}
	return nil
}

// execute is the only place StreamRunner is called. Remote stderr is capped
// and discarded. A command that finished successfully is reported as success
// even if the context was cancelled a moment later; only a failed command
// under a cancelled context maps to ClassCancelled, and an oversized stderr
// can no longer turn a classified exit code into a transport failure.
func (r *remoteRunner) execute(ctx context.Context, command string, stdin io.Reader, stdout io.Writer) error {
	if err := r.ready(); err != nil {
		return err
	}
	sink := &stderrSink{}
	code, err := r.run(ctx, r.target, command, stdin, stdout, sink)
	if err == nil && code == 0 {
		return nil
	}
	if ctx.Err() != nil {
		return classed(transfercore.ClassCancelled, msgCancelled, -1)
	}
	if err != nil {
		return classed(transfercore.ClassRemoteFailed, msgTransport, -1)
	}
	return classError(code)
}

// classError maps a remote exit code to a class with a fixed message.
func classError(code int) *transfercore.Error {
	switch code {
	case exitUnsupported, 126, 127:
		return classed(transfercore.ClassUnsupportedRemote, msgUnsupported, code)
	case exitRefusedPath:
		return classed(transfercore.ClassRefusedPath, msgRefused, code)
	case exitExists:
		return classed(transfercore.ClassExists, msgExists, code)
	case exitIntegrity:
		return classed(transfercore.ClassIntegrity, msgIntegrity, code)
	default:
		return classed(transfercore.ClassRemoteFailed, msgRemoteFailed, code)
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

// runListed runs a command that writes a bounded listing to stdout.
func (r *remoteRunner) runListed(ctx context.Context, command string, bound int64) ([]byte, error) {
	var buf bytes.Buffer
	b := &boundedWriter{w: &buf, remaining: bound}
	err := r.execute(ctx, command, nil, b)
	if b.overflow {
		return nil, classed(transfercore.ClassLimit, msgLimit, 0)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
