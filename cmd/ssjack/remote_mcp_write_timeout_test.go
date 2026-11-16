package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpWriteTimeoutTestBudget = 50 * time.Millisecond

type mcpWriteTimeoutWitness struct {
	pipe       *io.PipeWriter
	entered    chan struct{}
	closed     chan struct{}
	writeDone  chan struct{}
	enterOnce  sync.Once
	closeOnce  sync.Once
	writes     atomic.Int32
	closeCalls atomic.Int32
	mu         sync.Mutex
	writeErr   error
	closeErr   error
	writeData  []byte
}

func (w *mcpWriteTimeoutWitness) Write(p []byte) (int, error) {
	w.writes.Add(1)
	w.mu.Lock()
	w.writeData = append(w.writeData[:0], p...)
	w.mu.Unlock()
	w.enterOnce.Do(func() { close(w.entered) })
	n, err := w.pipe.Write(p)
	w.mu.Lock()
	w.writeErr = err
	w.mu.Unlock()
	close(w.writeDone)
	return n, err
}

func (w *mcpWriteTimeoutWitness) Close() error {
	w.closeCalls.Add(1)
	err := w.pipe.Close()
	w.closeOnce.Do(func() { close(w.closed) })
	w.mu.Lock()
	w.closeErr = err
	w.mu.Unlock()
	return err
}

func (w *mcpWriteTimeoutWitness) errors() (error, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeErr, w.closeErr
}

func (w *mcpWriteTimeoutWitness) payload() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.writeData...)
}

func newBlockedMCPWriteTimeoutConnection(t *testing.T, reader io.ReadCloser) (*mcpStdioConnection, *mcpWriteTimeoutWitness) {
	t.Helper()
	peer, pipe := io.Pipe()
	witness := &mcpWriteTimeoutWitness{pipe: pipe, entered: make(chan struct{}), closed: make(chan struct{}), writeDone: make(chan struct{})}
	connection := newMCPStdioTransport(reader, witness)
	connection.writeBudget = mcpWriteTimeoutTestBudget
	t.Cleanup(func() {
		// Releasing the peer first guarantees cleanup cannot strand an owned Write.
		_ = peer.Close()
		closed := make(chan struct{})
		go func() {
			_ = connection.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Error("owned timeout transport did not close and join")
		}
	})
	return connection, witness
}

func TestMCPStdioWriteTimeoutReturnsFromConnectedServer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame string
	}{
		{
			name:  "modern subscriptions listen",
			frame: `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},` + remoteMCPSubscriptionsTestMeta + `}}`,
		},
		{
			name:  "real fixture tool call",
			frame: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"timeout_fixture_tool","arguments":{},` + remoteMCPSubscriptionsTestMeta + `}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverInput, clientInput := io.Pipe()
			clientOutput, serverOutput := io.Pipe()
			witness := &mcpWriteTimeoutWitness{pipe: serverOutput, entered: make(chan struct{}), closed: make(chan struct{}), writeDone: make(chan struct{})}
			transport := newMCPStdioTransport(serverInput, witness)
			transport.writeBudget = mcpWriteTimeoutTestBudget
			server := mcp.NewServer(&mcp.Implementation{Name: "write-timeout-fixture", Version: "1"}, nil)
			configureMCPStdioServer(server)
			var toolCalls atomic.Int32
			server.AddTool(&mcp.Tool{Name: "timeout_fixture_tool", Description: "real write-timeout fixture", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				toolCalls.Add(1)
				return &mcp.CallToolResult{}, nil
			})
			var session interface {
				Wait() error
				Close() error
			}
			var waitStarted, requestStarted bool
			waitExited := make(chan struct{})
			requestExited := make(chan struct{})
			t.Cleanup(func() {
				// Keep the client input writer open until Wait has been asserted.
				_ = clientInput.Close()
				_ = serverInput.Close()
				_ = clientOutput.Close()
				_ = serverOutput.Close()
				closed := make(chan struct{})
				go func() {
					if session != nil {
						_ = session.Close()
					}
					_ = transport.Close()
					close(closed)
				}()
				select {
				case <-closed:
				case <-time.After(2 * time.Second):
					t.Error("connected server session and transport did not close")
				}
				if waitStarted {
					joinExited(t, waitExited, "connected server Wait worker did not join")
				}
				if requestStarted {
					joinExited(t, requestExited, "connected server request writer did not join")
				}
			})
			connected, err := server.Connect(context.Background(), transport, nil)
			if err != nil {
				t.Fatalf("real MCP server Connect failed: %v", err)
			}
			session = connected
			waitResult := make(chan error, 1)
			waitStarted = true
			go func() {
				waitResult <- session.Wait()
				close(waitExited)
			}()
			requestResult := make(chan error, 1)
			requestStarted = true
			go func() {
				_, writeErr := io.WriteString(clientInput, tc.frame+"\n")
				requestResult <- writeErr
				close(requestExited)
			}()
			if err := awaitSignal(t, requestResult, "connected server did not consume the request frame"); err != nil {
				t.Fatalf("client request frame write failed: %v", err)
			}
			awaitSignal(t, requestExited, "client request writer did not join")
			select {
			case <-witness.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("real MCP server response never entered the blocked pipe Write")
			}
			waitErr := awaitSignal(t, waitResult, "connected server Wait did not return before peer close or session.Close")
			if !errors.Is(waitErr, errMCPStdioWriteTimeout) {
				t.Fatalf("connected server Wait error = %v, want fixed stdio write timeout", waitErr)
			}
			if got := stdioCause(waitErr); got != "stdio-write-timeout" {
				t.Fatalf("stdioCause(%v) = %q, want stdio-write-timeout", waitErr, got)
			}
			awaitSignal(t, waitExited, "connected server Wait result was not joined")
			awaitSignal(t, witness.writeDone, "timed-out underlying output Write did not finish")
			if tc.name == "real fixture tool call" && toolCalls.Load() != 1 {
				t.Fatalf("real fixture tool calls = %d, want 1", toolCalls.Load())
			}
			if witness.closeCalls.Load() != 1 {
				t.Fatalf("timeout closed owned output writer %d times, want exactly once", witness.closeCalls.Load())
			}
			writeErr, closeErr := witness.errors()
			if !errors.Is(writeErr, io.ErrClosedPipe) {
				t.Fatalf("blocked underlying pipe Write error = %v, want io.ErrClosedPipe", writeErr)
			}
			if closeErr != nil {
				t.Fatalf("owned output pipe Close returned an unexpected error: %v", closeErr)
			}
			payload := witness.payload()
			switch tc.name {
			case "modern subscriptions listen":
				assertMCPSubscriptionsAck(t, string(payload), 1)
			case "real fixture tool call":
				result := sdkCallResults(t, string(payload), false, 1)[1]
				if result["resultType"] != "complete" {
					t.Fatalf("timed-out SDK tool response resultType = %v, want complete", result["resultType"])
				}
			default:
				t.Fatalf("unexpected connected timeout case %q", tc.name)
			}
			if err := transport.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, errMCPStdioWriteTimeout) {
				t.Fatalf("post-timeout Write = %v, want the fixed timeout refusal", err)
			}
			if witness.writes.Load() != 1 || witness.closeCalls.Load() != 1 {
				t.Fatalf("post-timeout Write touched the writer again: writes=%d closes=%d", witness.writes.Load(), witness.closeCalls.Load())
			}
			firstClose := closeMCPWriteTimeoutSession(t, session)
			secondClose := closeMCPWriteTimeoutSession(t, session)
			if (firstClose == nil) != (secondClose == nil) || (firstClose != nil && secondClose != nil && firstClose.Error() != secondClose.Error()) {
				t.Fatalf("repeated session.Close results were unstable: %v then %v", firstClose, secondClose)
			}
			if err := transport.Close(); err != nil {
				t.Fatalf("owned timeout transport Close failed: %v", err)
			}
			if witness.closeCalls.Load() != 1 {
				t.Fatalf("session shutdown closed output writer %d times, want exactly once", witness.closeCalls.Load())
			}
		})
	}
}

func closeMCPWriteTimeoutSession(t *testing.T, session interface{ Close() error }) error {
	t.Helper()
	closed := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		closed <- session.Close()
	}()
	err := awaitSignal(t, closed, "session.Close did not return within the cleanup budget")
	awaitSignal(t, exited, "session.Close worker did not join")
	return err
}

func TestMCPStdioWriteTimeoutCompletedLegacyBatchResponse(t *testing.T) {
	stream := []byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]` + "\n")
	connection, witness := newBlockedMCPWriteTimeoutConnection(t, io.NopCloser(bytes.NewReader(stream)))
	if _, err := connection.Read(context.Background()); err != nil {
		t.Fatalf("legacy batch did not decode: %v", err)
	}
	first, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(context.Background(), first); err != nil {
		t.Fatalf("incomplete legacy batch response was not buffered: %v", err)
	}
	writeDone := make(chan error, 1)
	writeExited := make(chan struct{})
	go func() {
		writeDone <- connection.Write(context.Background(), second)
		close(writeExited)
	}()
	t.Cleanup(func() {
		_ = witness.pipe.Close()
		joinExited(t, writeExited, "completed legacy batch writer did not join during cleanup")
	})
	select {
	case <-witness.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("completed legacy batch response did not enter the blocked pipe Write")
	}
	if err := awaitSignal(t, writeDone, "completed legacy batch response did not time out"); !errors.Is(err, errMCPStdioWriteTimeout) {
		t.Fatalf("completed legacy batch Write = %v, want fixed timeout", err)
	}
	awaitSignal(t, writeExited, "completed legacy batch writer did not join")
	awaitSignal(t, witness.writeDone, "completed legacy batch pipe Write did not finish")
	if witness.writes.Load() != 1 || witness.closeCalls.Load() != 1 {
		t.Fatalf("completed legacy batch did not use one joined output write: writes=%d closes=%d", witness.writes.Load(), witness.closeCalls.Load())
	}
	payload := witness.payload()
	if len(payload) == 0 || payload[0] != '[' || !bytes.HasSuffix(payload, []byte("\n")) {
		t.Fatalf("completed legacy batch was not written as one JSON-array frame: %q", payload)
	}
}

func TestMCPStdioWriteTimeoutStartsBeforeContendedWriteLock(t *testing.T) {
	connection, witness := newBlockedMCPWriteTimeoutConnection(t, io.NopCloser(bytes.NewReader(nil)))
	connection.writeMu.Lock()
	locked := true
	t.Cleanup(func() {
		if locked {
			connection.writeMu.Unlock()
		}
	})
	started := make(chan struct{})
	writeDone := make(chan error, 1)
	writeExited := make(chan struct{})
	go func() {
		close(started)
		writeDone <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
		close(writeExited)
	}()
	t.Cleanup(func() {
		if locked {
			connection.writeMu.Unlock()
			locked = false
		}
		_ = witness.pipe.Close()
		joinExited(t, writeExited, "contended Write worker did not join during cleanup")
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("contended Write worker did not start")
	}
	select {
	case <-witness.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("write timeout did not close the writer while the write lock was held")
	}
	connection.writeMu.Unlock()
	locked = false
	if err := awaitSignal(t, writeDone, "contended Write did not return after unlocking"); !errors.Is(err, errMCPStdioWriteTimeout) {
		t.Fatalf("contended Write = %v, want fixed timeout before lock acquisition", err)
	}
	awaitSignal(t, writeExited, "contended Write worker did not join")
	if witness.writes.Load() != 0 {
		t.Fatal("timed-out contended Write entered the underlying writer")
	}
}

func TestMCPStdioWriteTimeoutOnPreCanceledContext(t *testing.T) {
	inputReader, inputPeer := io.Pipe()
	connection, witness := newBlockedMCPWriteTimeoutConnection(t, inputReader)
	connection.writeBudget = remoteMCPStdioWriteBudget
	t.Cleanup(func() { _ = inputPeer.Close() })

	readResult := make(chan error, 1)
	readExited := make(chan struct{})
	go func() {
		defer close(readExited)
		_, err := connection.reader.Read(make([]byte, 1))
		readResult <- err
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writeResult := make(chan error, 1)
	writeExited := make(chan struct{})
	go func() {
		defer close(writeExited)
		writeResult <- connection.Write(ctx, &jsonrpc.Request{Method: "ping"})
	}()
	t.Cleanup(func() {
		_ = witness.pipe.Close()
		_ = inputPeer.Close()
		joinExited(t, writeExited, "pre-canceled Write worker did not join during cleanup")
		joinExited(t, readExited, "pre-canceled owned reader did not join during cleanup")
	})
	if err := awaitSignal(t, writeResult, "pre-canceled Write did not fail promptly"); !errors.Is(err, errMCPStdioWriteTimeout) {
		t.Fatalf("pre-canceled Write = %v, want fixed timeout error", err)
	}
	awaitSignal(t, writeExited, "pre-canceled Write worker did not join")
	if witness.writes.Load() != 0 || witness.closeCalls.Load() != 1 {
		t.Fatalf("pre-canceled Write touched writer unexpectedly: writes=%d closes=%d", witness.writes.Load(), witness.closeCalls.Load())
	}
	if err := awaitSignal(t, readResult, "pre-canceled Write did not close the owned reader"); err == nil {
		t.Fatal("pre-canceled Write left the owned reader open")
	}
	awaitSignal(t, readExited, "pre-canceled owned reader did not join")
	if err := connection.writeFailure(); !errors.Is(err, errMCPStdioWriteTimeout) {
		t.Fatalf("pre-canceled connection failure = %v, want fixed timeout", err)
	}
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, errMCPStdioWriteTimeout) {
		t.Fatalf("post-cancellation Write = %v, want the latched timeout", err)
	}
	if witness.writes.Load() != 0 || witness.closeCalls.Load() != 1 {
		t.Fatalf("post-cancellation Write touched writer unexpectedly: writes=%d closes=%d", witness.writes.Load(), witness.closeCalls.Load())
	}
}

func TestMCPStdioWriteFailureRefusesQueuedWrites(t *testing.T) {
	failure := errors.New("scripted writer failure")
	for _, tc := range []struct {
		name   string
		writer *scriptedWriter
		want   error
	}{
		{name: "short", writer: &scriptedWriter{short: true}, want: io.ErrShortWrite},
		{name: "failed", writer: &scriptedWriter{err: failure}, want: failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), tc.writer)
			for i := 0; i < 2; i++ {
				if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, tc.want) {
					t.Fatalf("Write %d error = %v, want original %v", i+1, err, tc.want)
				}
			}
			if tc.writer.writes.Load() != 1 || tc.writer.closes.Load() != 1 {
				t.Fatalf("failed frame allowed another underlying write: writes=%d closes=%d", tc.writer.writes.Load(), tc.writer.closes.Load())
			}
		})
	}
}

func TestMCPStdioWriteTimeoutOnCanceledContext(t *testing.T) {
	connection, witness := newBlockedMCPWriteTimeoutConnection(t, io.NopCloser(bytes.NewReader(nil)))
	connection.writeBudget = remoteMCPStdioWriteBudget
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writeDone := make(chan error, 1)
	writeExited := make(chan struct{})
	go func() {
		writeDone <- connection.Write(ctx, &jsonrpc.Request{Method: "ping"})
		close(writeExited)
	}()
	t.Cleanup(func() {
		_ = witness.pipe.Close()
		joinExited(t, writeExited, "canceled-context Write worker did not join during cleanup")
	})
	select {
	case <-witness.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled-context Write did not enter the blocked pipe")
	}
	cancel()
	if err := awaitSignal(t, writeDone, "canceled-context Write did not return after its pipe was closed"); !errors.Is(err, errMCPStdioWriteTimeout) {
		t.Fatalf("canceled-context Write = %v, want fixed timeout error", err)
	}
	awaitSignal(t, writeExited, "canceled-context Write worker did not join")
	awaitSignal(t, witness.writeDone, "canceled-context underlying pipe Write did not finish")
	writeErr, _ := witness.errors()
	if !errors.Is(writeErr, io.ErrClosedPipe) {
		t.Fatalf("canceled-context underlying pipe Write error = %v, want io.ErrClosedPipe", writeErr)
	}
	if witness.closeCalls.Load() != 1 {
		t.Fatalf("canceled-context timeout closed output writer %d times, want once", witness.closeCalls.Load())
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("canceled-context transport Close failed: %v", err)
	}
	if witness.closeCalls.Load() != 1 {
		t.Fatal("transport Close repeated the timeout callback's writer close")
	}
}
