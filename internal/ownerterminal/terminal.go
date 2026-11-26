// Package ownerterminal provides real terminals for CI process acceptance only.
package ownerterminal

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
)

var ErrTerminal = errors.New("synthetic terminal process failed")

type Command struct {
	Executable, Directory, UnixBridge string
	Args, Environment                 []string
}

// Callers must drain Output through EOF, including during cancellation.
type Terminal struct {
	Input      io.WriteCloser
	Output     io.ReadCloser
	done       chan struct{}
	watch      chan struct{}
	pid        int
	stopMu     sync.Mutex
	stopSent   bool
	stopErr    error
	stop       func()
	err        error
	once       sync.Once
	outputOnce sync.Once
	outputErr  error
}

func Start(ctx context.Context, command Command) (*Terminal, error) {
	if ctx == nil || ctx.Err() != nil || command.Executable == "" {
		return nil, ErrTerminal
	}
	if command.Environment == nil {
		command.Environment = os.Environ()
	}
	return start(ctx, command)
}

func (t *Terminal) Wait(ctx context.Context) error {
	if ctx == nil {
		return ErrTerminal
	}
	select {
	case <-t.done:
		<-t.watch
		return t.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stopErrorClass renders a bounded classification of a signal failure.
func stopErrorClass(err error) string {
	switch {
	case errors.Is(err, os.ErrProcessDone):
		return "process-already-finished"
	case errors.Is(err, syscall.EPERM):
		return "eperm"
	case errors.Is(err, syscall.ESRCH):
		return "esrch"
	default:
		return "other"
	}
}

func (t *Terminal) stopSignalState() string {
	t.stopMu.Lock()
	defer t.stopMu.Unlock()
	switch {
	case !t.stopSent:
		return "not-sent"
	case t.stopErr == nil:
		return "sent-ok"
	default:
		return "error:" + stopErrorClass(t.stopErr)
	}
}

func (t *Terminal) Close(ctx context.Context) error {
	if t == nil {
		return nil
	}
	t.once.Do(func() { _ = t.Input.Close(); t.stop() })
	err := t.Wait(ctx)
	select {
	case <-t.done:
		t.outputOnce.Do(func() { t.outputErr = t.Output.Close() })
	default:
		return err
	}
	if err != nil {
		return err
	}
	return t.outputErr
}

func (t *Terminal) observe(ctx context.Context) {
	go func() {
		defer close(t.watch)
		select {
		case <-ctx.Done():
			t.stop()
		case <-t.done:
		}
	}()
}
