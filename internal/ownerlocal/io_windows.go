package ownerlocal

import (
	"context"
	"errors"
	"io"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// overlapped joins kernel completion and cancellation before unpinning memory.
func overlapped(ctx context.Context, handle windows.Handle, data []byte, operation func(*windows.Overlapped, *uint32) error) (int, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer windows.CloseHandle(event)
	overlap := windows.Overlapped{HEvent: event}
	var pinned runtime.Pinner
	pinned.Pin(&overlap)
	if len(data) != 0 {
		pinned.Pin(&data[0])
	}
	defer pinned.Unpin()
	var count uint32
	pinned.Pin(&count)
	err = operation(&overlap, &count)
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		if ctx.Err() != nil {
			return int(count), ctx.Err()
		}
		return int(count), err
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = windows.CancelIoEx(handle, &overlap)
		close(joined)
	})
	err = windows.GetOverlappedResult(handle, &overlap, &count, true)
	if !stop() {
		<-joined
	}
	if ctx.Err() != nil {
		return int(count), ctx.Err()
	}
	return int(count), err
}

func mergeLifetime(lifetime, caller context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(lifetime)
	joined := make(chan struct{})
	stop := context.AfterFunc(caller, func() { cancel(); close(joined) })
	return ctx, func() {
		if !stop() {
			<-joined
		}
		cancel()
	}
}

type pipeConnection struct {
	handle windows.Handle
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	active sync.WaitGroup
	closed bool
	once   sync.Once
	err    error
}

func newPipeConnection(handle windows.Handle) *pipeConnection {
	ctx, cancel := context.WithCancel(context.Background())
	return &pipeConnection{handle: handle, ctx: ctx, cancel: cancel}
}
func (c *pipeConnection) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancel()
		c.mu.Unlock()
		_ = windows.CancelIoEx(c.handle, nil)
		c.active.Wait()
		c.err = windows.CloseHandle(c.handle)
	})
	return c.err
}
func (c *pipeConnection) Read(ctx context.Context, data []byte) (int, error) {
	return c.transfer(ctx, data, true)
}
func (c *pipeConnection) Write(ctx context.Context, data []byte) (int, error) {
	return c.transfer(ctx, data, false)
}
func (c *pipeConnection) transfer(caller context.Context, data []byte, read bool) (int, error) {
	if caller == nil || caller.Err() != nil || len(data) > 1<<20 {
		return 0, ErrClosed
	}
	if len(data) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ErrClosed
	}
	c.active.Add(1)
	c.mu.Unlock()
	defer c.active.Done()
	ctx, done := mergeLifetime(c.ctx, caller)
	defer done()
	n, err := overlapped(ctx, c.handle, data, func(overlap *windows.Overlapped, count *uint32) error {
		if read {
			return windows.ReadFile(c.handle, data, count, overlap)
		}
		return windows.WriteFile(c.handle, data, count, overlap)
	})
	if ctx.Err() != nil {
		c.cancel()
		return n, ctx.Err()
	}
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) {
		return n, io.EOF
	}
	if err != nil {
		return n, ErrUnavailable
	}
	return n, nil
}
