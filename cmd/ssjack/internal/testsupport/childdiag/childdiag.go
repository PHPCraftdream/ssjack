// Package childdiag provides shared failure-only diagnostics helpers for
// cmd/ssjack tests: bounded output tails, tee capture, exec/process child
// evidence, terminal wait timing, phase timestamps, deadline helpers and
// capture-wait diagnostics.
package childdiag

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
)

// Failure-only diagnostics for non-owner child processes in cmd/ssjack
// tests: command NAME (never arguments), pid, exit status/signal, phase
// timings and size-capped output tails. Secret values are never rendered;
// only digests and bounded tails of already-captured output are printed.
const TailKeep = 64 << 10

// Tail keeps the last bytes of a child's captured output for
// failure-only diagnostics, independent of any capture cleared in teardown.
type Tail struct {
	mu   sync.Mutex
	data []byte
}

func NewTail() *Tail { return &Tail{} }

func (t *Tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = append(t.data, p...)
	if len(t.data) > TailKeep {
		t.data = append([]byte(nil), t.data[len(t.data)-TailKeep:]...)
	}
	return len(p), nil
}

func (t *Tail) Snapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.data)
}

// tee passes a child output stream through while recording it.
type tee struct {
	io.Reader
	closer io.Closer
	tail   *Tail
}

// TeeOutput wraps a terminal output reader; downstream captures see the
// same bytes while the tail records them for failure-only evidence.
func TeeOutput(output io.ReadCloser, tail *Tail) io.ReadCloser {
	return &tee{Reader: output, closer: output, tail: tail}
}

func (t *tee) Read(p []byte) (int, error) {
	n, err := t.Reader.Read(p)
	if n > 0 {
		_, _ = t.tail.Write(p[:n])
	}
	return n, err
}

func (t *tee) Close() error {
	if t.closer == nil {
		return nil
	}
	return t.closer.Close()
}

func commandName(command *exec.Cmd) string {
	if command == nil || len(command.Args) == 0 {
		return ""
	}
	return filepath.Base(command.Args[0])
}

func pid(command *exec.Cmd) int {
	if command == nil || command.Process == nil {
		return 0
	}
	return command.Process.Pid
}

// ExecDiag prints failure-only evidence for a finished exec-based child:
// command name, pid, exit status/signal, output size, digest and a 16 KiB
// tail of the captured output.
func ExecDiag(t *testing.T, what string, command *exec.Cmd, output []byte, err error) {
	t.Helper()
	if err == nil {
		return
	}
	t.Logf("child evidence: what=%s name=%s pid=%d exit=%v output-bytes=%d digest=%s\noutput tail:%s",
		what, commandName(command), pid(command), err, len(output),
		flakediag.Short(output), flakediag.Tail(string(output), 16*1024))
}

// ProcessOnFailure registers failure-only evidence for a spawned child:
// command name, pid, start time, elapsed time, exit status once reaped and a
// 16 KiB tail of the recorded output plus a goroutine dump. Passing runs add
// no work.
func ProcessOnFailure(t *testing.T, what string, command *exec.Cmd, tail *Tail, started time.Time) {
	t.Helper()
	flakediag.OnFailure(t, func() string {
		exit := "still running or unjoined"
		if command.ProcessState != nil {
			exit = command.ProcessState.String()
		}
		out := ""
		if tail != nil {
			out = "\noutput tail:" + flakediag.Tail(tail.Snapshot(), 16*1024)
		}
		return "child process: what=" + what +
			" name=" + commandName(command) +
			" pid=" + fmt.Sprint(pid(command)) +
			" started=" + started.Format(time.RFC3339) +
			" elapsed=" + time.Since(started).Round(time.Millisecond).String() +
			" exit=" + exit + out +
			"\ngoroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
}

// TerminalWait wraps a PTY terminal wait, preserving the caller's
// timeout and error semantics, and adds failure-only phase timing on error.
func TerminalWait(t *testing.T, what string, ctx context.Context, terminal *ownerterminal.Terminal) error {
	t.Helper()
	started := time.Now()
	err := terminal.Wait(ctx)
	if err != nil {
		t.Logf("terminal wait failed: what=%s elapsed=%s err=%v",
			what, time.Since(started).Round(time.Millisecond), err)
	}
	return err
}

// Phases records named phase timestamps for failure-only evidence.
type Phases struct {
	mu     sync.Mutex
	origin time.Time
	phases []string
}

func NewPhases() *Phases { return &Phases{origin: time.Now()} }

// Mark records that a phase completed, with its offset from the origin.
func (p *Phases) Mark(what string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phases = append(p.phases, fmt.Sprintf("%s@+%s", what, time.Since(p.origin).Round(time.Millisecond)))
}

func (p *Phases) Render() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return "phases: " + strings.Join(p.phases, " ")
}

// DeadlineOf returns the remaining budget of ctx, or a minimal positive
// budget when no deadline is set.
func DeadlineOf(ctx context.Context) time.Duration {
	if ctx == nil {
		return time.Millisecond
	}
	remaining := time.Until(DeadlineTime(ctx))
	if remaining <= 0 {
		remaining = time.Millisecond
	}
	return remaining
}

func DeadlineTime(ctx context.Context) (deadline time.Time) {
	if ctx == nil {
		return time.Now().Add(-time.Second)
	}
	deadline, _ = ctx.Deadline()
	return deadline
}

// CaptureWaitDiag waits for expected terminal output through flakediag
// polling, preserving the caller's fatal message and timeout semantics, and
// registers failure-only evidence via WaitForDesc's OnFailure hook.
func CaptureWaitDiag(t *testing.T, ctx context.Context, capture *ownerterminal.Capture, expected, failMessage string) {
	t.Helper()
	done, _, lastErr := flakediag.WaitForDesc(t, "terminal output "+expected, DeadlineOf(ctx), func() (string, bool, error) {
		if capture.Contains([]byte(expected)) {
			return "", true, nil
		}
		stop, cancel := context.WithCancel(context.Background())
		cancel()
		if capture.Join(stop) == nil {
			return "process ended before the expected output", false, errors.New("process ended")
		}
		if err := ctx.Err(); err != nil {
			return "wait context ended", false, err
		}
		return "output not seen yet", false, nil
	})
	_ = lastErr
	if !done {
		t.Fatal(failMessage)
	}
}
