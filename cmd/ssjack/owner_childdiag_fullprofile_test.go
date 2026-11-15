package main

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
)

// ownerChildTail keeps the last bytes of a child's captured output for
// failure-only diagnostics. It is independent of ownerterminal captures, so
// evidence survives capture.Clear in teardown.
const ownerChildTailKeep = 64 << 10

type ownerChildTail struct {
	mu   sync.Mutex
	data []byte
}

func newOwnerChildTail() *ownerChildTail { return &ownerChildTail{} }

func (t *ownerChildTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = append(t.data, p...)
	if len(t.data) > ownerChildTailKeep {
		t.data = append([]byte(nil), t.data[len(t.data)-ownerChildTailKeep:]...)
	}
	return len(p), nil
}

func (t *ownerChildTail) snapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.data)
}

// ownerChildTee passes through a terminal output reader while recording it.
type ownerChildTee struct {
	io.Reader
	closer io.Closer
	tail   *ownerChildTail
}

// teeOwnerChildOutput wraps terminal.Output; the capture sees the same bytes.
func teeOwnerChildOutput(output io.ReadCloser, tail *ownerChildTail) io.ReadCloser {
	return &ownerChildTee{Reader: output, closer: output, tail: tail}
}

func (t *ownerChildTee) Read(p []byte) (int, error) {
	n, err := t.Reader.Read(p)
	if n > 0 {
		_, _ = t.tail.Write(p[:n])
	}
	return n, err
}

func (t *ownerChildTee) Close() error {
	if t.closer == nil {
		return nil
	}
	return t.closer.Close()
}

// ownerChildExecFail prints failure-only evidence for a finished exec-based
// driver child: command name (never arguments), pid, exit status, output size,
// a digest and a 16 KiB tail of the already-captured combined output.
func ownerChildExecFail(t *testing.T, what string, command *exec.Cmd, output []byte, err error) {
	t.Helper()
	if err == nil {
		return
	}
	name := ""
	if len(command.Args) > 0 {
		name = filepath.Base(command.Args[0])
	}
	pid := 0
	if command.Process != nil {
		pid = command.Process.Pid
	}
	t.Logf("owner child evidence: what=%s name=%s pid=%d exit=%v output-bytes=%d digest=%s\noutput tail:%s",
		what, name, pid, err, len(output), flakediag.Short(output), flakediag.Tail(string(output), 16*1024))
}

// ownerChildTerminal registers failure-only evidence for a PTY terminal child:
// command name, start time, elapsed time, exit status and a 16 KiB tail of the
// captured output plus a goroutine dump. Passing runs add no work.
func ownerChildTerminal(t *testing.T, what, executableName string, terminal *ownerterminal.Terminal, tail *ownerChildTail, started time.Time) {
	t.Helper()
	flakediag.OnFailure(t, func() string {
		state := "still running or unjoined"
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		switch err := terminal.Wait(ctx); {
		case err == nil:
			state = "exited cleanly"
		case ctx.Err() == nil:
			// The child ended on its own: the error is its exit status.
			state = "exited with error: " + flakediag.Tail(err.Error(), 200)
		}
		stop()
		return "owner terminal child: what=" + what +
			" name=" + filepath.Base(executableName) +
			" started=" + started.Format(time.RFC3339) +
			" elapsed=" + time.Since(started).Round(time.Millisecond).String() +
			" exit=" + state +
			"\noutput tail:" + flakediag.Tail(tail.snapshot(), 16*1024) +
			"\ngoroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
}

// captureWaitDiag waits for expected terminal output through flakediag
// polling, preserving the caller's fatal message and timeout semantics, and
// registers failure-only evidence (what was waited for, elapsed, last state,
// goroutine dump) via WaitForDesc's OnFailure hook.
func captureWaitDiag(t *testing.T, ctx context.Context, capture *ownerterminal.Capture, expected, failMessage string) {
	t.Helper()
	remaining := time.Until(deadlineOf(ctx))
	if remaining <= 0 {
		remaining = time.Millisecond
	}
	done, _, lastErr := flakediag.WaitForDesc(t, "terminal output "+expected, remaining, func() (string, bool, error) {
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

func deadlineOf(ctx context.Context) (deadline time.Time) {
	if ctx == nil {
		return time.Now().Add(-time.Second)
	}
	deadline, _ = ctx.Deadline()
	return deadline
}
