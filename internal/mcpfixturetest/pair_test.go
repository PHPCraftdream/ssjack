package mcpfixturetest

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

const helperLimit = time.Second

func awaitWithin[T any](ch <-chan T, timeout time.Duration) (T, bool) {
	select {
	case value := <-ch:
		return value, true
	case <-time.After(timeout):
		var zero T
		return zero, false
	}
}

func await[T any](t *testing.T, label string, ch <-chan T) (T, bool) {
	t.Helper()
	value, ok := awaitWithin(ch, helperLimit)
	if !ok {
		t.Errorf("%s timed out", label)
	}
	return value, ok
}

func TestAwaitTimeoutPath(t *testing.T) {
	if _, ok := awaitWithin(make(chan struct{}), time.Millisecond); ok {
		t.Fatal("awaitWithin unexpectedly received a value")
	}
}

type readResult struct {
	message jsonrpc.Message
	err     error
}

func startRead(t *testing.T, conn *connection, ctx context.Context) (<-chan readResult, func()) {
	t.Helper()
	result, done := make(chan readResult, 1), make(chan struct{})
	go func() {
		defer close(done)
		message, err := conn.Read(ctx)
		result <- readResult{message: message, err: err}
	}()
	return result, func() {
		select {
		case <-done:
		case <-time.After(helperLimit):
			t.Error("read worker did not join")
		}
	}
}

func startWrite(t *testing.T, conn *connection, ctx context.Context, message jsonrpc.Message) (<-chan error, func()) {
	t.Helper()
	result, done := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(done)
		result <- conn.Write(ctx, message)
	}()
	return result, func() {
		select {
		case <-done:
		case <-time.After(helperLimit):
			t.Error("write worker did not join")
		}
	}
}

func startClose(t *testing.T, conn *connection) (<-chan error, func()) {
	t.Helper()
	result, done := make(chan error, 1), make(chan struct{})
	go func() { defer close(done); result <- conn.Close() }()
	return result, func() {
		select {
		case <-done:
		case <-time.After(helperLimit):
			t.Error("close worker did not join")
		}
	}
}

// Cleanup releases injected barriers and cancels workers before initiating Close
// asynchronously, then bounds every worker join. Close is never called inline.
func cleanupWorkers(t *testing.T, conn *connection, release func(), cancels []context.CancelFunc, joins ...func()) {
	t.Helper()
	if release != nil {
		release()
	}
	for _, cancel := range cancels {
		cancel()
	}
	_, joinCleanupClose := startClose(t, conn)
	joinCleanupClose()
	for _, join := range joins {
		if join != nil {
			join()
		}
	}
}

func TestPairCodecAndOneShot(t *testing.T) {
	leftTransport, rightTransport := NewPair()
	ctx, cancel := context.WithTimeout(context.Background(), helperLimit)
	defer cancel()
	left, err := leftTransport.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	right, err := rightTransport.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if left.SessionID() != "fixture-left" || right.SessionID() != "fixture-right" || left.SessionID() == right.SessionID() {
		t.Fatalf("session IDs: %q %q", left.SessionID(), right.SessionID())
	}
	message := &jsonrpc.Request{Method: "fixture/test"}
	if err := left.Write(ctx, message); err != nil {
		t.Fatal(err)
	}
	got, err := right.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request, ok := got.(*jsonrpc.Request)
	if !ok || request.Method != message.Method {
		t.Fatalf("decoded message = %#v", got)
	}
	if _, err := leftTransport.Connect(ctx); err == nil {
		t.Fatal("second Connect succeeded")
	}
}

func TestCloseCommitsEOFBeforeReadWakes(t *testing.T) {
	leftTransport, rightTransport := NewPair()
	conn := leftTransport.(*transport).conn
	peerTransport := rightTransport.(*transport)
	commitBarrier := make(chan struct {
		terminalEOF bool
		changedOpen bool
	}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var originalChanged <-chan struct{}
	conn.closeHook = func() {
		terminalEOF := conn.inbox.terminal && conn.inbox.terminalErr == nil
		changedOpen := true
		select {
		case <-originalChanged:
			changedOpen = false
		default:
		}
		commitBarrier <- struct {
			terminalEOF bool
			changedOpen bool
		}{terminalEOF: terminalEOF, changedOpen: changedOpen}
		<-release
	}
	readParked := make(chan struct{})
	conn.waitHook = func() { close(readParked) }
	readCtx, cancelRead := context.WithTimeout(context.Background(), helperLimit)
	read, joinRead := startRead(t, conn, readCtx)
	closeResult, joinClose := (<-chan error)(nil), func() {}
	defer func() { cleanupWorkers(t, conn, unblock, []context.CancelFunc{cancelRead}, joinRead, joinClose) }()

	if _, ok := await(t, "blocked Read barrier", readParked); !ok {
		return
	}
	conn.inbox.mu.Lock()
	originalChanged = conn.inbox.changed
	conn.inbox.mu.Unlock()
	if peerTransport.connected.Load() {
		t.Fatal("peer unexpectedly connected before local Close")
	}
	closeResult, joinClose = startClose(t, conn)
	commit, ok := await(t, "EOF committed barrier", commitBarrier)
	if !ok {
		return
	}
	if !commit.terminalEOF || !commit.changedOpen {
		t.Fatalf("close hook state = terminal EOF %v, notification still open %v; want true, true", commit.terminalEOF, commit.changedOpen)
	}
	if result, ok := nonblockingRead(read); ok {
		t.Fatalf("Read resumed before committed EOF was released: %+v", result)
	}
	unblock()
	closeErr, ok := await(t, "Close result", closeResult)
	if !ok || closeErr != nil {
		t.Fatalf("Close error = %v", closeErr)
	}
	result, ok := await(t, "Read result", read)
	if !ok || result.err != io.EOF {
		t.Fatalf("Read error = %v, want EOF", result.err)
	}
	peer, err := rightTransport.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	peerReadCtx, cancelPeerRead := context.WithTimeout(context.Background(), helperLimit)
	defer cancelPeerRead()
	if _, err := peer.Read(peerReadCtx); err != io.EOF {
		t.Fatalf("peer Read error = %v, want EOF", err)
	}
}

func TestQueuedReadFailuresSurviveCloseAndCanceledContext(t *testing.T) {
	decodeFailure := frame{data: []byte("not-json")}
	readSentinel := errors.New("application read failure")
	for _, test := range []struct {
		name string
		item frame
		want error
	}{
		{name: "closed pipe", item: frame{err: io.ErrClosedPipe}, want: io.ErrClosedPipe},
		{name: "network closed", item: frame{err: net.ErrClosed}, want: net.ErrClosed},
		{name: "context canceled", item: frame{err: context.Canceled}, want: context.Canceled},
		{name: "application sentinel", item: frame{err: readSentinel}, want: readSentinel},
		{name: "decode failure", item: decodeFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			leftTransport, _ := NewPair()
			conn := leftTransport.(*transport).conn
			if err := conn.inbox.enqueue(test.item, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), helperLimit)
			defer cancel()
			if err := conn.Close(); err != nil {
				cancel()
				t.Fatal(err)
			}
			cancel()
			_, err := conn.Read(ctx)
			if test.want != nil {
				if err != test.want {
					t.Fatalf("Read error = %v, want identical error %v", err, test.want)
				}
			} else if err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("Read error = %v, want a decode failure", err)
			}
		})
	}
}

func TestInjectedWriteAndCloseErrorsRemainIdentical(t *testing.T) {
	leftTransport, _ := NewPair()
	conn := leftTransport.(*transport).conn
	writeSentinel, encodeSentinel, closeSentinel := errors.New("write"), errors.New("encode"), errors.New("close")
	message := &jsonrpc.Request{Method: "fixture/test"}
	conn.writeErr = writeSentinel
	if err := conn.Write(context.Background(), message); err != writeSentinel {
		t.Fatalf("write error = %v", err)
	}
	conn.writeErr = nil
	conn.encode = func(jsonrpc.Message) ([]byte, error) { return nil, encodeSentinel }
	if err := conn.Write(context.Background(), message); err != encodeSentinel {
		t.Fatalf("encode error = %v", err)
	}
	conn.closeErr = closeSentinel
	if err := conn.Close(); err != closeSentinel {
		t.Fatalf("Close error = %v", err)
	}
	if err := conn.Close(); err != closeSentinel {
		t.Fatalf("repeat Close error = %v", err)
	}
	if err := conn.Write(context.Background(), message); err != io.EOF {
		t.Fatalf("Write after own Close = %v, want EOF", err)
	}
}

func nonblockingRead(ch <-chan readResult) (readResult, bool) {
	select {
	case result := <-ch:
		return result, true
	default:
		return readResult{}, false
	}
}
