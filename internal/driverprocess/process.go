// Package driverprocess contains an internal, disabled process transport prerequisite.
package driverprocess

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

const MaxOutput = (64 << 10) + 4

var ErrOutputLimit = errors.New("driver process output limit exceeded")
var ErrSemantic = errors.New("driver response rejected")
var ErrUnsupported = errors.New("driver process execution unavailable")
var ErrDeadlineRequired = errors.New("driver process requires a context deadline")

// Result retains bounded, untrusted child output for diagnostics; it is not a model/API surface.
type Result struct {
	Response, Stderr     []byte
	ExitErr, SemanticErr error
}
type cappedBuffer struct {
	mu       sync.Mutex
	b        bytes.Buffer
	limit    int
	exceeded bool
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	left := w.limit - w.b.Len()
	if left <= 0 {
		w.exceeded = true
		return 0, ErrOutputLimit
	}
	if len(p) > left {
		_, _ = w.b.Write(p[:left])
		w.exceeded = true
		return left, ErrOutputLimit
	}
	return w.b.Write(p)
}
func (w *cappedBuffer) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.b.Bytes()...)
}
func (w *cappedBuffer) exceededLimit() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exceeded
}

// processCapability is an internal seam: only code in this package can implement it.
type processCapability interface {
	command(context.Context) *exec.Cmd
}

type stderrObserver interface {
	observeStderr([]byte)
}

// execute runs the bounded framed protocol lifecycle for a trusted command capability.
func execute(ctx context.Context, capability processCapability, request []byte) (Result, error) {
	if ctx == nil {
		return Result{}, ErrDeadlineRequired
	}
	if capability == nil {
		return Result{}, ErrUnsupported
	}
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	if _, ok := ctx.Deadline(); !ok {
		return Result{}, ErrDeadlineRequired
	}
	req, err := driverprotocol.ValidateStructuralRequest(request)
	if err != nil {
		return Result{}, ErrSemantic
	}
	cmd := capability.command(ctx)
	if cmd == nil {
		return Result{}, ErrUnsupported
	}
	cmd.WaitDelay = 2 * time.Second
	// Replace any capability-provided environment with a minimal inherited-platform environment.
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if v := os.Getenv("SystemRoot"); v != "" {
		cmd.Env = append(cmd.Env, "SystemRoot="+v)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Result{}, err
	}
	out, stderr := &cappedBuffer{limit: MaxOutput}, &cappedBuffer{limit: MaxOutput}
	var kill sync.Once
	var processMu sync.Mutex
	var started bool
	var killRequested bool
	killChild := func() {
		kill.Do(func() {
			processMu.Lock()
			if started && cmd.Process != nil {
				_ = cmd.Process.Kill()
			} else {
				killRequested = true
			}
			processMu.Unlock()
			// Closing the pipe first can block behind a stalled write on Windows.
			_ = stdin.Close()
		})
	}
	cmd.Stdout = writerFunc(func(p []byte) (int, error) {
		n, e := out.Write(p)
		if e != nil {
			killChild()
		}
		return n, e
	})
	cmd.Stderr = writerFunc(func(p []byte) (int, error) {
		n, e := stderr.Write(p)
		if observer, ok := capability.(stderrObserver); ok {
			observer.observeStderr(p[:n])
		}
		if e != nil {
			killChild()
		}
		return n, e
	})
	if err = cmd.Start(); err != nil {
		_ = stdin.Close()
		return Result{}, err
	}
	processMu.Lock()
	started = true
	if killRequested && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	processMu.Unlock()
	callbackDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() { killChild(); close(callbackDone) })
	defer func() {
		if !stopCancel() {
			<-callbackDone
		}
	}()
	writeDone := make(chan error, 1)
	go func() {
		e := driverframe.Write(stdin, request)
		ce := stdin.Close()
		if e == nil {
			e = ce
		}
		writeDone <- e
	}()
	var writeErr error
	finished := false
	select {
	case writeErr = <-writeDone:
		finished = true
	case <-ctx.Done():
		killChild()
	case <-time.After(10 * time.Second):
		killChild()
	}
	exitErr := cmd.Wait()
	if !finished {
		writeErr = <-writeDone
	}
	result := Result{Response: out.Bytes(), Stderr: stderr.Bytes(), ExitErr: exitErr}
	if out.exceededLimit() || stderr.exceededLimit() {
		return result, ErrOutputLimit
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if writeErr != nil {
		return result, writeErr
	}
	if exitErr != nil {
		return result, exitErr
	}
	f := bytes.NewReader(result.Response)
	payload, err := driverframe.Read(f)
	if err == nil {
		err = driverframe.RequireEOF(f)
	}
	if err == nil {
		_, err = driverprotocol.ValidateStructuralResponse(req, payload)
	}
	if err != nil {
		result.SemanticErr = err
		return result, ErrSemantic
	}
	return result, nil
}

// Execute remains disabled; model-provided paths and arguments are never accepted.
func Execute(context.Context, string, []string, []byte) (Result, error) {
	return Result{}, ErrUnsupported
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
