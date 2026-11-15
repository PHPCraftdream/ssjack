package main

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
const childTailKeep = 64 << 10

// childTail keeps the last bytes of a child's captured output for
// failure-only diagnostics, independent of any capture cleared in teardown.
type childTail struct {
	mu   sync.Mutex
	data []byte
}

func newChildTail() *childTail { return &childTail{} }

func (t *childTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = append(t.data, p...)
	if len(t.data) > childTailKeep {
		t.data = append([]byte(nil), t.data[len(t.data)-childTailKeep:]...)
	}
	return len(p), nil
}

func (t *childTail) snapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.data)
}

// childTee passes a child output stream through while recording it.
type childTee struct {
	io.Reader
	closer io.Closer
	tail   *childTail
}

// teeChildOutput wraps a terminal output reader; downstream captures see the
// same bytes while the tail records them for failure-only evidence.
func teeChildOutput(output io.ReadCloser, tail *childTail) io.ReadCloser {
	return &childTee{Reader: output, closer: output, tail: tail}
}

func (t *childTee) Read(p []byte) (int, error) {
	n, err := t.Reader.Read(p)
	if n > 0 {
		_, _ = t.tail.Write(p[:n])
	}
	return n, err
}

func (t *childTee) Close() error {
	if t.closer == nil {
		return nil
	}
	return t.closer.Close()
}

func childCommandName(command *exec.Cmd) string {
	if command == nil || len(command.Args) == 0 {
		return ""
	}
	return filepath.Base(command.Args[0])
}

func childPID(command *exec.Cmd) int {
	if command == nil || command.Process == nil {
		return 0
	}
	return command.Process.Pid
}

// childExecDiag prints failure-only evidence for a finished exec-based child:
// command name, pid, exit status/signal, output size, digest and a 16 KiB
// tail of the captured output.
func childExecDiag(t *testing.T, what string, command *exec.Cmd, output []byte, err error) {
	t.Helper()
	if err == nil {
		return
	}
	t.Logf("child evidence: what=%s name=%s pid=%d exit=%v output-bytes=%d digest=%s\noutput tail:%s",
		what, childCommandName(command), childPID(command), err, len(output),
		flakediag.Short(output), flakediag.Tail(string(output), 16*1024))
}

// childProcessOnFailure registers failure-only evidence for a spawned child:
// command name, pid, start time, elapsed time, exit status once reaped and a
// 16 KiB tail of the recorded output plus a goroutine dump. Passing runs add
// no work.
func childProcessOnFailure(t *testing.T, what string, command *exec.Cmd, tail *childTail, started time.Time) {
	t.Helper()
	flakediag.OnFailure(t, func() string {
		exit := "still running or unjoined"
		if command.ProcessState != nil {
			exit = command.ProcessState.String()
		}
		out := ""
		if tail != nil {
			out = "\noutput tail:" + flakediag.Tail(tail.snapshot(), 16*1024)
		}
		return "child process: what=" + what +
			" name=" + childCommandName(command) +
			" pid=" + fmt.Sprint(childPID(command)) +
			" started=" + started.Format(time.RFC3339) +
			" elapsed=" + time.Since(started).Round(time.Millisecond).String() +
			" exit=" + exit + out +
			"\ngoroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
}

// childTerminalWait wraps a PTY terminal wait, preserving the caller's
// timeout and error semantics, and adds failure-only phase timing on error.
func childTerminalWait(t *testing.T, what string, ctx context.Context, terminal *ownerterminal.Terminal) error {
	t.Helper()
	started := time.Now()
	err := terminal.Wait(ctx)
	if err != nil {
		t.Logf("terminal wait failed: what=%s elapsed=%s err=%v",
			what, time.Since(started).Round(time.Millisecond), err)
	}
	return err
}

// childPhases records named phase timestamps for failure-only evidence.
type childPhases struct {
	mu     sync.Mutex
	origin time.Time
	phases []string
}

func newChildPhases() *childPhases { return &childPhases{origin: time.Now()} }

// mark records that a phase completed, with its offset from the origin.
func (p *childPhases) mark(what string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phases = append(p.phases, fmt.Sprintf("%s@+%s", what, time.Since(p.origin).Round(time.Millisecond)))
}

func (p *childPhases) render() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return "phases: " + strings.Join(p.phases, " ")
}

// childDeadlineOf returns the remaining budget of ctx, or a minimal positive
// budget when no deadline is set.
func childDeadlineOf(ctx context.Context) time.Duration {
	if ctx == nil {
		return time.Millisecond
	}
	remaining := time.Until(childDeadlineTime(ctx))
	if remaining <= 0 {
		remaining = time.Millisecond
	}
	return remaining
}

func childDeadlineTime(ctx context.Context) (deadline time.Time) {
	if ctx == nil {
		return time.Now().Add(-time.Second)
	}
	deadline, _ = ctx.Deadline()
	return deadline
}

// childCaptureWaitDiag waits for expected terminal output through flakediag
// polling, preserving the caller's fatal message and timeout semantics, and
// registers failure-only evidence via WaitForDesc's OnFailure hook.
func childCaptureWaitDiag(t *testing.T, ctx context.Context, capture *ownerterminal.Capture, expected, failMessage string) {
	t.Helper()
	done, _, lastErr := flakediag.WaitForDesc(t, "terminal output "+expected, childDeadlineOf(ctx), func() (string, bool, error) {
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
