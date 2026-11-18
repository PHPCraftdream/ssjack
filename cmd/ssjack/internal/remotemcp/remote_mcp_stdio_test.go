package remotemcp

import (
	"bytes"
	"context"
	"errors"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fragmentedMCPInput struct {
	data []byte
	n    int
}

func (r *fragmentedMCPInput) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), min(r.n, len(r.data)))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}
func (*fragmentedMCPInput) Close() error { return nil }

type nopWriteCloser struct{ *bytes.Buffer }

func (nopWriteCloser) Close() error { return nil }

func readBoundedMCP(t *testing.T, input io.ReadCloser) ([]byte, error) {
	t.Helper()
	return io.ReadAll(newBoundedMCPStdioReader(input))
}

func TestBoundedMCPStdioReaderPreservesFragmentsAndDoesNotFilter(t *testing.T) {
	frame := []byte(`{"jsonrpc":"2.0","id":"known-literal","method":"tools/call","params":{"name":"known-literal","arguments":{"token":"known-literal"}}}` + "\n")
	got, err := readBoundedMCP(t, &fragmentedMCPInput{data: append([]byte(nil), frame...), n: 3})
	if err != nil {
		t.Fatal("fragmented valid MCP frame was refused")
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("stdio reader changed the original JSON-RPC bytes: got %q", got)
	}
}

// Unknown versions pass the reader unchanged: the SDK negotiates them down,
// and a refusal here would end the single-use session.
func TestMCPProtocolVersionsReachNegotiationUnchanged(t *testing.T) {
	for _, version := range []string{mcpProtocol20241105, mcpProtocol20250326, mcpProtocol20250618, "2025-11-25", "2099-01-01"} {
		frame := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + version + `"}}` + "\n")
		got, err := readBoundedMCP(t, &fragmentedMCPInput{data: append([]byte(nil), frame...), n: len(frame)})
		if err != nil || !bytes.Equal(got, frame) {
			t.Fatalf("initialize with version %q did not pass the reader unchanged: %v", version, err)
		}
	}
}

func TestBoundedMCPStdioRejectsDuplicateAdmissionFieldsBeforeYield(t *testing.T) {
	for _, frame := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"unsupported","method":"ping"}` + "\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01","protocolVersion":"2025-06-18"}}` + "\n",
	} {
		input := &fragmentedMCPInput{data: []byte(frame), n: len(frame)}
		reader := newBoundedMCPStdioReader(input)
		buf := make([]byte, 1)
		if n, err := reader.Read(buf); n != 0 || err == nil {
			t.Fatalf("duplicate admission field was not rejected before yielding frame bytes: %q", frame)
		}
	}
}

func TestBoundedMCPStdioMessageByteLimitAtEOF(t *testing.T) {
	base := []byte(`{"method":"ping"}`)
	for _, size := range []int{maxMCPStdioMessage, maxMCPStdioMessage + 1} {
		frame := append(append([]byte(nil), base...), bytes.Repeat([]byte{' '}, size-len(base))...)
		_, err := readBoundedMCP(t, &fragmentedMCPInput{data: frame, n: 4093})
		if size == maxMCPStdioMessage && err != nil {
			t.Fatal("exactly bounded JSON frame was refused")
		}
		if size == maxMCPStdioMessage+1 && err == nil {
			t.Fatal("one-byte-oversized JSON frame was admitted")
		}
	}
}

func TestBoundedMCPStdioMessageCountAndMethods(t *testing.T) {
	frame := []byte(`{"method":"ping"}` + "\n")
	var stream []byte
	for range maxMCPStdioMessages + 1 {
		stream = append(stream, frame...)
	}
	if _, err := readBoundedMCP(t, &fragmentedMCPInput{data: stream, n: 8191}); err == nil {
		t.Fatal("stream exceeding the bounded message count was admitted")
	}
	batch := `[` + strings.TrimSuffix(strings.Repeat(string(frame[:len(frame)-1])+",", maxMCPStdioMessages+1), ",") + `]` + "\n"
	if _, err := readBoundedMCP(t, &fragmentedMCPInput{data: []byte(batch), n: 2047}); err == nil {
		t.Fatal("oversized JSON-RPC batch was admitted")
	}
	// The reader frames; the connection enforces the method surface.
	for _, method := range []string{"$/arbitrary", "resources/read", "prompts/list", "server/discover"} {
		unknown := []byte(`{"jsonrpc":"2.0","method":"` + method + `"}` + "\n")
		if got, err := readBoundedMCP(t, &fragmentedMCPInput{data: unknown, n: len(unknown)}); err != nil || !bytes.Equal(got, unknown) {
			t.Fatalf("framing of method %q was not passed through unchanged: %v", method, err)
		}
	}
	for _, frame := range []string{`{"jsonrpc":"2.0","id":1,"method":7}`, `{"jsonrpc":"1.0","id":1,"method":"ping"}`, `[1]`} {
		if _, err := readBoundedMCP(t, &fragmentedMCPInput{data: []byte(frame + "\n"), n: len(frame) + 1}); err == nil {
			t.Fatalf("malformed message was admitted: %s", frame)
		}
	}
}

// Close must abandon, not join, a blocked physical read: it returns while the
// read is still blocked, later reads get the fixed closed error, and cleanup
// releases the abandoned worker.
func TestBoundedMCPStdioCloseAbandonsBlockedRead(t *testing.T) {
	source := newMCPHostileReadInput()
	reader := newBoundedMCPStdioReader(source)
	readDone := make(chan error, 1)
	readExited := make(chan struct{})
	go func() {
		defer close(readExited)
		_, err := reader.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("read did not enter the hostile source")
	}
	closeDone := make(chan error, 1)
	closeExited := make(chan struct{})
	go func() {
		defer close(closeExited)
		closeDone <- reader.Close()
	}()
	t.Cleanup(func() {
		source.release()
		joinExited(t, readExited, "abandoned physical read did not exit after release")
		joinExited(t, closeExited, "hostile reader close worker did not join")
	})
	if err := awaitSignal(t, closeDone, "hostile-source reader Close did not return while the read stayed blocked"); err != nil {
		t.Fatalf("abandoning reader Close returned an error: %v", err)
	}
	awaitSignal(t, closeExited, "reader close worker did not join")
	if err := awaitSignal(t, readDone, "logical Read did not return after Close abandoned it"); !errors.Is(err, errMCPStdioReaderClosed) {
		t.Fatalf("abandoned logical Read = %v, want the fixed closed error", err)
	}
	awaitSignal(t, readExited, "logical read worker did not join")
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, errMCPStdioReaderClosed) {
		t.Fatalf("post-abandonment Read = %v, want the fixed closed error", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("repeated reader close returned an unexpected error: %v", err)
	}
	if source.closes.Load() != 1 {
		t.Fatalf("hostile source was closed %d times, want exactly once", source.closes.Load())
	}
}

// mcpHostileReadInput blocks in Read and its Close ignores the blocked read.
type mcpHostileReadInput struct {
	reader     *io.PipeReader
	writer     *io.PipeWriter
	entered    chan struct{}
	readExited chan struct{}
	enterOnce  sync.Once
	exitOnce   sync.Once
	closes     atomic.Int32
}

func newMCPHostileReadInput() *mcpHostileReadInput {
	reader, writer := io.Pipe()
	return &mcpHostileReadInput{reader: reader, writer: writer, entered: make(chan struct{}), readExited: make(chan struct{})}
}

func (r *mcpHostileReadInput) Read(p []byte) (int, error) {
	r.enterOnce.Do(func() { close(r.entered) })
	n, err := r.reader.Read(p)
	r.exitOnce.Do(func() { close(r.readExited) })
	return n, err
}

// Close ignores the blocked read: it neither releases nor joins it.
func (r *mcpHostileReadInput) Close() error {
	r.closes.Add(1)
	return nil
}

// release unblocks the abandoned physical read; only cleanup calls it.
func (r *mcpHostileReadInput) release() { _ = r.writer.Close() }

func TestMCPStdioConnectionDecodesFramesAndBatches(t *testing.T) {
	frame := []byte(`{"jsonrpc":"2.0","id":"known-literal","method":"ping"}` + "\n")
	batch := []byte(`[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]` + "\n")
	stream := append(append([]byte(nil), frame...), batch...)
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(stream)), nopWriteCloser{bytes.NewBuffer(nil)})
	first, err := connection.Read(context.Background())
	if err != nil {
		t.Fatal("single bounded frame did not decode")
	}
	request, ok := first.(*jsonrpc.Request)
	if !ok || request.Method != "ping" || request.ID.Raw() != "known-literal" {
		t.Fatal("single frame did not decode as the original request")
	}
	second, err := connection.Read(context.Background())
	if err != nil {
		t.Fatal("batch head did not decode")
	}
	if notification, ok := second.(*jsonrpc.Request); !ok || notification.ID.IsValid() {
		t.Fatal("batch head lost its notification shape")
	}
	third, err := connection.Read(context.Background())
	if err != nil {
		t.Fatal("queued batch message did not decode")
	}
	if call, ok := third.(*jsonrpc.Request); !ok || call.ID.Raw() != int64(2) {
		t.Fatal("queued batch message lost its id")
	}
	if _, err := connection.Read(context.Background()); err != io.EOF {
		t.Fatal("connection did not end at EOF")
	}
}

const mcpWriteTimeoutTestBudget = 50 * time.Millisecond

type mcpWriteTimeoutWitness struct {
	pipe *io.PipeWriter
	// hostileClose makes Close ignore the blocked pipe write.
	hostileClose bool
	entered      chan struct{}
	closed       chan struct{}
	writeDone    chan struct{}
	enterOnce    sync.Once
	closeOnce    sync.Once
	writes       atomic.Int32
	closeCalls   atomic.Int32
	mu           sync.Mutex
	writeErr     error
	closeErr     error
	writeData    []byte
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
	var err error
	if !w.hostileClose {
		err = w.pipe.Close()
	}
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

// The write budget lapses while another owner holds the write slot: the
// waiter returns the fixed timeout without entering the writer, and the
// owned writer is closed even though the slot was never released.
func TestMCPStdioWriteTimeoutFiresWhileWriteSlotIsHeld(t *testing.T) {
	connection, witness := newBlockedMCPWriteTimeoutConnection(t, io.NopCloser(bytes.NewReader(nil)))
	<-connection.writeToken
	started := make(chan struct{})
	writeDone := make(chan error, 1)
	writeExited := make(chan struct{})
	go func() {
		close(started)
		writeDone <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
		close(writeExited)
	}()
	t.Cleanup(func() {
		_ = witness.pipe.Close()
		joinExited(t, writeExited, "held-slot Write worker did not join during cleanup")
	})
	awaitSignal(t, started, "held-slot Write worker did not start")
	select {
	case <-witness.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("write timeout did not close the writer while the write slot was held")
	}
	if err := awaitSignal(t, writeDone, "held-slot Write did not return the fixed timeout"); !errors.Is(err, errMCPStdioWriteTimeout) {
		t.Fatalf("held-slot Write = %v, want fixed timeout without entering the writer", err)
	}
	awaitSignal(t, writeExited, "held-slot Write worker did not join")
	if witness.writes.Load() != 0 {
		t.Fatal("timed-out held-slot Write entered the underlying writer")
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

// The real SDK server must end promptly against an output writer whose Write
// blocks and whose Close does not release it: the response Write returns the
// fixed timeout, Wait and transport Close return while the physical write
// stays blocked, the first frame is the only one ever attempted, and cleanup
// releases the abandoned worker.
func TestMCPStdioHostileWriterIgnoresCloseAndRefusesFollowingFrames(t *testing.T) {
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
			witness := &mcpWriteTimeoutWitness{pipe: serverOutput, hostileClose: true, entered: make(chan struct{}), closed: make(chan struct{}), writeDone: make(chan struct{})}
			transport := newMCPStdioTransport(serverInput, witness)
			transport.writeBudget = mcpWriteTimeoutTestBudget
			server := mcp.NewServer(&mcp.Implementation{Name: "hostile-writer-fixture", Version: "1"}, nil)
			configureMCPStdioServer(server)
			var toolCalls atomic.Int32
			server.AddTool(&mcp.Tool{Name: "timeout_fixture_tool", Description: "hostile writer fixture", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
				// Release the abandoned physical write first, then close the
				// session and transport, then join every owned worker.
				_ = clientOutput.Close()
				_ = serverOutput.Close()
				awaitSignal(t, witness.writeDone, "abandoned hostile physical write did not finish after release")
				_ = clientInput.Close()
				_ = serverInput.Close()
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
					t.Error("hostile-writer session and transport did not close")
				}
				if waitStarted {
					joinExited(t, waitExited, "hostile-writer Wait worker did not join")
				}
				if requestStarted {
					joinExited(t, requestExited, "hostile-writer request writer did not join")
				}
			})
			connected, err := server.Connect(context.Background(), transport, nil)
			if err != nil {
				t.Fatalf("hostile-writer server Connect failed: %v", err)
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
			if err := awaitSignal(t, requestResult, "server did not consume the request frame"); err != nil {
				t.Fatalf("client request frame write failed: %v", err)
			}
			awaitSignal(t, requestExited, "client request writer did not join")
			select {
			case <-witness.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("server response never entered the blocked hostile Write")
			}
			waitErr := awaitSignal(t, waitResult, "hostile writer kept the server Wait blocked past the write budget")
			if !errors.Is(waitErr, errMCPStdioWriteTimeout) {
				t.Fatalf("hostile-writer Wait error = %v, want fixed stdio write timeout", waitErr)
			}
			if got := stdioCause(waitErr); got != "stdio-write-timeout" {
				t.Fatalf("stdioCause(%v) = %q, want stdio-write-timeout", waitErr, got)
			}
			awaitSignal(t, waitExited, "hostile-writer Wait result was not joined")
			payload := witness.payload()
			switch tc.name {
			case "modern subscriptions listen":
				assertMCPSubscriptionsAck(t, string(payload), 1)
			case "real fixture tool call":
				result := sdkCallResults(t, string(payload), false, 1)[1]
				if result["resultType"] != "complete" {
					t.Fatalf("hostile-writer tool response resultType = %v, want complete", result["resultType"])
				}
			default:
				t.Fatalf("unexpected hostile-writer case %q", tc.name)
			}
			if err := transport.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, errMCPStdioWriteTimeout) {
				t.Fatalf("post-timeout Write = %v, want the fixed timeout refusal", err)
			}
			if witness.writes.Load() != 1 || witness.closeCalls.Load() != 1 {
				t.Fatalf("post-timeout Write touched the hostile writer: writes=%d closes=%d", witness.writes.Load(), witness.closeCalls.Load())
			}
			if err := transport.Close(); err != nil {
				t.Fatalf("hostile-writer transport Close failed while the physical write stayed blocked: %v", err)
			}
			if witness.closeCalls.Load() != 1 {
				t.Fatalf("shutdown closed hostile output writer %d times, want exactly once", witness.closeCalls.Load())
			}
			if tc.name == "real fixture tool call" && toolCalls.Load() != 1 {
				t.Fatalf("hostile fixture tool calls = %d, want 1", toolCalls.Load())
			}
		})
	}
}

// A real SDK server whose stdio input blocks in Read and whose Close ignores
// the blocked read must still end promptly: shutdown abandons the read
// instead of joining it.
func TestMCPStdioHostileReaderCannotHoldServerShutdown(t *testing.T) {
	source := newMCPHostileReadInput()
	clientOutput, serverOutput := io.Pipe()
	transport := newMCPStdioTransport(source, serverOutput)
	server := mcp.NewServer(&mcp.Implementation{Name: "hostile-reader-fixture", Version: "1"}, nil)
	configureMCPStdioServer(server)
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	runExited := make(chan struct{})
	go func() {
		defer close(runExited)
		runErr <- server.Run(ctx, transport)
	}()
	t.Cleanup(func() {
		cancel()
		source.release()
		_ = clientOutput.Close()
		_ = serverOutput.Close()
		joinExited(t, runExited, "hostile-reader server run worker did not join")
	})
	select {
	case <-source.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("server read loop never entered the hostile source")
	}
	cancel()
	runErrValue := awaitSignal(t, runErr, "hostile reader kept server.Run blocked past cancellation")
	if !errors.Is(runErrValue, context.Canceled) {
		t.Fatalf("hostile-reader Run error = %v, want context cancellation", runErrValue)
	}
	awaitSignal(t, runExited, "hostile-reader run worker did not join")
	if err := transport.Close(); err != nil {
		t.Fatalf("hostile-reader transport Close failed: %v", err)
	}
	if source.closes.Load() != 1 {
		t.Fatalf("hostile source was closed %d times, want exactly once", source.closes.Load())
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
