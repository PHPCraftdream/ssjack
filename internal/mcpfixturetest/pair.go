package mcpfixturetest

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	frameLimit = 1 << 20
	queueLimit = 32
)

var errFrameTooLarge = errors.New("fixture frame too large")
var errNilContext = errors.New("fixture context is nil")

type frame struct {
	data []byte
	err  error
}

type inbox struct {
	mu            sync.Mutex
	frames        []frame
	terminal      bool
	terminalErr   error
	terminalOwner *atomic.Bool
	changed       chan struct{}
}

func newInbox() *inbox { return &inbox{changed: make(chan struct{})} }

func (q *inbox) changeLocked() {
	close(q.changed)
	q.changed = make(chan struct{})
}

func (q *inbox) rejectWriteLocked(owner *atomic.Bool) error {
	if q.terminal {
		if owner != nil && q.terminalOwner == owner {
			return io.EOF
		}
		return io.ErrClosedPipe
	}
	if owner != nil && owner.Load() {
		return io.EOF
	}
	return nil
}

func (q *inbox) rejectWrite(owner *atomic.Bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.rejectWriteLocked(owner)
}

func (q *inbox) enqueue(item frame, owner *atomic.Bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.rejectWriteLocked(owner); err != nil {
		return err
	}
	if len(q.frames) == queueLimit {
		return errFrameTooLarge
	}
	q.frames = append(q.frames, item)
	q.changeLocked()
	return nil
}

func (q *inbox) take(ctx context.Context, beforeWait func()) (frame, error) {
	if ctx == nil {
		return frame{}, errNilContext
	}
	for {
		q.mu.Lock()
		if len(q.frames) != 0 {
			item := q.frames[0]
			q.frames[0] = frame{}
			q.frames = q.frames[1:]
			q.changeLocked()
			q.mu.Unlock()
			return item, nil
		}
		if q.terminal {
			err := q.terminalErr
			q.mu.Unlock()
			if err != nil {
				return frame{}, err
			}
			return frame{}, io.EOF
		}
		if err := ctx.Err(); err != nil {
			q.mu.Unlock()
			return frame{}, err
		}
		changed := q.changed
		q.mu.Unlock()
		if beforeWait != nil {
			beforeWait()
			beforeWait = nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
		}
	}
}

func (q *inbox) terminate(err error, owner *atomic.Bool, beforeWake func()) {
	q.mu.Lock()
	if !q.terminal {
		q.terminal = true
		q.terminalErr = err
		q.terminalOwner = owner
		// This narrow test seam holds notification until the committed terminal
		// state is observable, making Close/Read ordering deterministic.
		if beforeWake != nil {
			beforeWake()
		}
		q.changeLocked()
	}
	q.mu.Unlock()
}

type connection struct {
	inbox    *inbox
	peer     *inbox
	id       string
	closed   atomic.Bool
	close    sync.Once
	closeErr error
	// Hooks and writeErr are narrow fault/order seams for fixture tests; the
	// frame codec and inbox remain the exercised transport path.
	closeHook   func()
	writeHook   func()
	publishHook func()
	writeErr    error
	encode      func(jsonrpc.Message) ([]byte, error)
	waitHook    func()
}

func (c *connection) Read(ctx context.Context) (jsonrpc.Message, error) {
	item, err := c.inbox.take(ctx, c.waitHook)
	if err != nil {
		return nil, err
	}
	if item.err != nil {
		return nil, item.err
	}
	defer clear(item.data)
	return jsonrpc.DecodeMessage(item.data)
}

func (c *connection) Write(ctx context.Context, message jsonrpc.Message) error {
	if c.closed.Load() {
		return c.peer.rejectWrite(&c.closed)
	}
	if ctx == nil {
		return errNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.writeHook != nil {
		c.writeHook()
	}
	if c.writeErr != nil {
		return c.writeErr
	}
	data, err := c.encode(message)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > frameLimit {
		clear(data)
		return errFrameTooLarge
	}
	if c.publishHook != nil {
		c.publishHook()
	}
	if err := c.peer.enqueue(frame{data: data}, &c.closed); err != nil {
		clear(data)
		return err
	}
	return nil
}

func (c *connection) Close() error {
	c.close.Do(func() {
		c.closed.Store(true)
		c.inbox.terminate(nil, &c.closed, c.closeHook)
		c.peer.terminate(nil, &c.closed, nil)
	})
	return c.closeErr
}

func (c *connection) SessionID() string { return c.id }

type transport struct {
	conn      *connection
	connected atomic.Bool
}

func (t *transport) Connect(ctx context.Context) (mcp.Connection, error) {
	if ctx == nil {
		return nil, errNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !t.connected.CompareAndSwap(false, true) {
		return nil, errors.New("fixture transport already connected")
	}
	return t.conn, nil
}

func NewPair() (mcp.Transport, mcp.Transport) {
	left, right := newInbox(), newInbox()
	leftConn := &connection{inbox: left, peer: right, id: "fixture-left", encode: jsonrpc.EncodeMessage}
	rightConn := &connection{inbox: right, peer: left, id: "fixture-right", encode: jsonrpc.EncodeMessage}
	return &transport{conn: leftConn}, &transport{conn: rightConn}
}
