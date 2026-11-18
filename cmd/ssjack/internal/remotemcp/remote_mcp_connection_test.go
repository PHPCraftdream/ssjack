package remotemcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// scriptedWriter owns entry witnesses, an in-write block, a held return gate,
// and the underlying close result; release is idempotent and single-owner.
type scriptedWriter struct {
	entries     chan struct{}
	block       chan struct{}
	returnGate  chan struct{}
	closeSignal chan struct{}

	blockOnce  sync.Once
	returnOnce sync.Once
	short      bool
	err        error
	closeErr   error

	writes     atomic.Int32
	closes     atomic.Int32
	active     atomic.Int32
	overlapped atomic.Bool
}

func (w *scriptedWriter) Write(p []byte) (int, error) {
	if w.active.Add(1) != 1 {
		w.overlapped.Store(true)
	}
	defer w.active.Add(-1)
	if w.entries != nil {
		w.entries <- struct{}{}
	}
	if w.block != nil {
		<-w.block
	}
	w.writes.Add(1)
	defer func() {
		if w.returnGate != nil {
			<-w.returnGate
		}
	}()
	if w.short {
		return len(p) - 1, nil
	}
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

func (w *scriptedWriter) Close() error {
	first := w.closes.Add(1) == 1
	if first {
		if w.block != nil {
			w.blockOnce.Do(func() { close(w.block) })
		}
		if w.closeSignal != nil {
			close(w.closeSignal)
		}
	}
	return w.closeErr
}

// release unblocks the gates exactly once; repeats and post-Close calls are no-ops.
func (w *scriptedWriter) release() {
	if w.block != nil {
		w.blockOnce.Do(func() { close(w.block) })
	}
	if w.returnGate != nil {
		w.returnOnce.Do(func() { close(w.returnGate) })
	}
}

func TestMCPStdioConnectionRefusesShortAndFailedWrites(t *testing.T) {
	failure := errors.New("synthetic owned write failure")
	for _, tt := range []struct {
		name   string
		writer *scriptedWriter
		want   error
	}{
		{"short", &scriptedWriter{short: true}, io.ErrShortWrite},
		{"failed", &scriptedWriter{err: failure}, failure},
	} {
		connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), tt.writer)
		if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, tt.want) {
			t.Fatalf("%s owned write lost its exact fixed error: %v", tt.name, err)
		}
		if tt.writer.writes.Load() != 1 {
			t.Fatalf("%s underlying writer was not exercised exactly once", tt.name)
		}
	}
}

func TestMCPStdioConnectionRetainsGenuineCloseResult(t *testing.T) {
	closeRefusal := errors.New("synthetic owned close refusal")
	writer := &scriptedWriter{closeErr: closeRefusal}
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), writer)
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); err != nil {
		t.Fatalf("successful owned write was rejected: %v", err)
	}
	if err := connection.Close(); !errors.Is(err, closeRefusal) {
		t.Fatalf("owned close lost its retained result: %v", err)
	}
	if err := connection.Close(); !errors.Is(err, closeRefusal) {
		t.Fatalf("repeated owned close did not retain its result: %v", err)
	}
	if writer.closes.Load() != 1 {
		t.Fatal("repeated close re-closed the owned writer")
	}
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, errMCPStdioWriterClosed) {
		t.Fatalf("write after close was not refused with the fixed error: %v", err)
	}
}

func TestMCPStdioConnectionSerializesContendedWrites(t *testing.T) {
	writer := &scriptedWriter{entries: make(chan struct{}, 4), block: make(chan struct{})}
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), writer)
	firstExited := make(chan struct{})
	secondExited := make(chan struct{})
	errs := make(chan error, 2)
	t.Cleanup(func() {
		writer.release()
		joinExited(t, firstExited, "first owned write worker did not exit")
		joinExited(t, secondExited, "second owned write worker did not exit")
	})
	// Pre-taking the write slot delays both launches behind the slot but does
	// not prove either goroutine reached the select before the slot returned;
	// entry coverage is scheduler-dependent.
	<-connection.writeToken
	go func() {
		defer close(firstExited)
		errs <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
	}()
	go func() {
		defer close(secondExited)
		errs <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
	}()
	connection.writeToken <- struct{}{}
	awaitSignal(t, writer.entries, "first owned write did not enter the underlying writer")
	select {
	case <-writer.entries:
		t.Fatal("second owned write entered the writer while the first held it")
	case <-time.After(50 * time.Millisecond):
	}
	if writer.overlapped.Load() {
		t.Fatal("concurrent owned writes overlapped inside the writer")
	}
	writer.release()
	if err := awaitSignal(t, errs, "first contended owned write did not return"); err != nil {
		t.Fatal(err)
	}
	if err := awaitSignal(t, errs, "second contended owned write did not return"); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, firstExited, "first owned write worker did not exit")
	awaitSignal(t, secondExited, "second owned write worker did not exit")
	if writer.overlapped.Load() {
		t.Fatal("contended owned writes overlapped before both completed")
	}
}

func TestMCPStdioConnectionCloseJoinsHeldWriteAndRetainsResult(t *testing.T) {
	closeRefusal := errors.New("synthetic owned close refusal")
	writer := &scriptedWriter{entries: make(chan struct{}, 8), block: make(chan struct{}), returnGate: make(chan struct{}), closeSignal: make(chan struct{}), closeErr: closeRefusal}
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), writer)
	const closers = 3
	writeExited := make(chan struct{})
	closeExited := make(chan struct{})
	closerExited := make(chan struct{}, closers-1)
	var closeLaunched atomic.Int32
	t.Cleanup(func() {
		writer.release()
		joinExited(t, writeExited, "held write worker did not exit")
		if n := int(closeLaunched.Load()); n > 0 {
			joinExited(t, closeExited, "first close worker did not exit")
			for i := 0; i < n-1; i++ {
				joinExited(t, closerExited, "concurrent close worker did not exit")
			}
		}
	})
	writeDone := make(chan error, 1)
	go func() {
		defer close(writeExited)
		writeDone <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
	}()
	awaitSignal(t, writer.entries, "owned write did not enter the blocked writer")
	closeDone := make(chan error, closers)
	closeLaunched.Add(1)
	go func() {
		defer close(closeExited)
		closeDone <- connection.Close()
	}()
	awaitSignal(t, writer.closeSignal, "owned close did not release the underlying writer")
	for i := 0; i < closers-1; i++ {
		closeLaunched.Add(1)
		go func() {
			defer func() { closerExited <- struct{}{} }()
			closeDone <- connection.Close()
		}()
	}
	select {
	case err := <-closeDone:
		t.Fatalf("a close returned before the held write returned: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	writer.release()
	for i := 0; i < closers; i++ {
		if err := awaitSignal(t, closeDone, "owned close did not join the held write"); !errors.Is(err, closeRefusal) {
			t.Fatalf("owned close lost its retained result: %v", err)
		}
	}
	if err := awaitSignal(t, writeDone, "held owned write did not return"); err != nil {
		t.Fatalf("admitted blocked write did not complete once released: %v", err)
	}
	if writer.closes.Load() != 1 {
		t.Fatal("owned writer was closed more than once")
	}
}

func TestMCPStdioConnectionRefusesTrackedResponseAfterClose(t *testing.T) {
	stream := []byte(`[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]` + "\n")
	rawResponse := []byte(`{"jsonrpc":"2.0","id":2,"result":{}}`)
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(stream)), &scriptedWriter{})
	if _, err := connection.Read(context.Background()); err != nil {
		t.Fatalf("legacy batch head did not decode: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("owned close failed: %v", err)
	}
	response, err := jsonrpc.DecodeMessage(rawResponse)
	if err != nil {
		t.Fatalf("synthetic tracked response did not decode: %v", err)
	}
	if err := connection.Write(context.Background(), response); !errors.Is(err, errMCPStdioWriterClosed) {
		t.Fatalf("tracked batch response after close was not refused with the fixed error: %v", err)
	}
	connection.batchMu.Lock()
	tracked := len(connection.batches)
	connection.batchMu.Unlock()
	if tracked != 1 {
		t.Fatalf("refused tracked response mutated batch state: %d entries", tracked)
	}
}

// Ordinary writes keep frame order and the ordinary shutdown results: two
// frames in order, Close nil, later writes refused with the fixed closed
// error, Close idempotent.
func TestMCPStdioConnectionOrdinaryShutdownKeepsOrderAndResults(t *testing.T) {
	buffer := &bytes.Buffer{}
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), nopWriteCloser{buffer})
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); err != nil {
		t.Fatalf("first ordinary write failed: %v", err)
	}
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "tools/list"}); err != nil {
		t.Fatalf("second ordinary write failed: %v", err)
	}
	frames := bytes.Split(buffer.Bytes(), []byte("\n"))
	if len(frames) != 3 || len(frames[0]) == 0 || len(frames[1]) == 0 || len(frames[2]) != 0 {
		t.Fatalf("ordinary writes did not produce exactly two newline frames: %q", buffer.String())
	}
	for i, want := range []string{"ping", "tools/list"} {
		message, err := jsonrpc.DecodeMessage(frames[i])
		if err != nil {
			t.Fatalf("frame %d did not decode: %v", i+1, err)
		}
		request, ok := message.(*jsonrpc.Request)
		if !ok || request.Method != want {
			t.Fatalf("frame %d = %#v, want method %q in order", i+1, message, want)
		}
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("ordinary close failed: %v", err)
	}
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, errMCPStdioWriterClosed) {
		t.Fatalf("write after ordinary close = %v, want the fixed closed refusal", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("repeated ordinary close failed: %v", err)
	}
}

func TestMCPStdioConnectionRefusesAdmissionWhileShutdownHeld(t *testing.T) {
	writer := &scriptedWriter{entries: make(chan struct{}, 4), block: make(chan struct{}), returnGate: make(chan struct{}), closeSignal: make(chan struct{})}
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), writer)
	writeExited := make(chan struct{})
	closeExited := make(chan struct{})
	var closeLaunched atomic.Int32
	t.Cleanup(func() {
		writer.release()
		joinExited(t, writeExited, "held write worker did not exit")
		if closeLaunched.Load() == 1 {
			joinExited(t, closeExited, "close worker did not exit")
		}
	})
	writeDone := make(chan error, 1)
	go func() {
		defer close(writeExited)
		writeDone <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
	}()
	awaitSignal(t, writer.entries, "owned write did not enter the blocked writer")
	closeLaunched.Add(1)
	closeDone := make(chan error, 1)
	go func() {
		defer close(closeExited)
		closeDone <- connection.Close()
	}()
	awaitSignal(t, writer.closeSignal, "owned close did not release the underlying writer")
	select {
	case err := <-closeDone:
		t.Fatalf("shutdown returned while the admitted write was still held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, errMCPStdioWriterClosed) {
		t.Fatalf("write admitted while shutdown was held lost the fixed refusal: %v", err)
	}
	writer.release()
	if err := awaitSignal(t, writeDone, "admitted held write did not return after release"); err != nil {
		t.Fatalf("admitted held write failed once released: %v", err)
	}
	if err := awaitSignal(t, closeDone, "owned close did not return"); err != nil {
		t.Fatalf("owned close failed: %v", err)
	}
	if writer.closes.Load() != 1 {
		t.Fatal("owned writer was closed more than once")
	}
}

// Regression for the 2026-11-15 drop: Claude Code probes stdio servers with
// server/discover before initialize and offers protocol 2025-11-25. The bridge
// must preserve the session while answering supported modern discovery requests.

// assertMethodNotFound checks one reply: the given ids, each carrying exactly
// the standard method-not-found error and no result.
func assertMethodNotFound(t *testing.T, line string, wantArray bool, wantIDs ...int64) {
	t.Helper()
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || (trimmed[0] == '[') != wantArray {
		t.Fatalf("refusal container mismatch: want array=%v got %q", wantArray, trimmed)
	}
	raws := []json.RawMessage{json.RawMessage(trimmed)}
	if wantArray {
		raws = nil
		if err := json.Unmarshal([]byte(trimmed), &raws); err != nil {
			t.Fatalf("refusal array did not decode: %q", trimmed)
		}
	}
	if len(raws) != len(wantIDs) {
		t.Fatalf("refusal carried %d responses, want %d: %q", len(raws), len(wantIDs), trimmed)
	}
	for i, raw := range raws {
		var envelope struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      int64           `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   *struct {
				Code    int64  `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("refusal did not decode: %q", raw)
		}
		if envelope.JSONRPC != "2.0" || envelope.ID != wantIDs[i] || envelope.Result != nil || envelope.Error == nil || envelope.Error.Code != -32601 {
			t.Fatalf("refusal %d is not method-not-found for id %d: %q", i, wantIDs[i], raw)
		}
	}
}

func readRequest(t *testing.T, connection *mcpStdioConnection, method string, id any) {
	t.Helper()
	message, err := connection.Read(context.Background())
	if err != nil {
		t.Fatalf("read before %s failed: %v", method, err)
	}
	request, ok := message.(*jsonrpc.Request)
	if !ok || request.Method != method || request.ID.Raw() != id {
		t.Fatalf("connection yielded %#v, want %s with id %v", message, method, id)
	}
}

func TestMCPStdioConnectionPassesDiscoverAndDropsUnknownNotification(t *testing.T) {
	stream := strings.Join([]string{
		`{"jsonrpc":"2.0","id":7,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`,
		`{"jsonrpc":"2.0","id":8,"method":"ping"}`,
	}, "\n") + "\n"
	out := bytes.NewBuffer(nil)
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream)), nopWriteCloser{out})
	readRequest(t, connection, "server/discover", int64(7))
	if out.Len() != 0 {
		t.Fatalf("connection refused discover before the SDK could handle it: %q", out.String())
	}
	readRequest(t, connection, "ping", int64(8))
	if out.Len() != 0 {
		t.Fatalf("connection replied to an admitted request: %q", out.String())
	}
	if _, err := connection.Read(context.Background()); err != io.EOF {
		t.Fatalf("connection did not end at EOF: %v", err)
	}
}

func TestMCPStdioConnectionRefusesEveryOutsideMethod(t *testing.T) {
	for i, method := range []string{"subscriptions/listen", "resources/list", "resources/read", "prompts/list", "completion/complete", "logging/setLevel", "$/arbitrary"} {
		id := int64(100 + i)
		stream := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q}`+"\n"+`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n", id, method)
		out := bytes.NewBuffer(nil)
		connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream)), nopWriteCloser{out})
		readRequest(t, connection, "tools/list", int64(1))
		assertMethodNotFound(t, out.String(), false, id)
	}
}

func TestMCPStdioConnectionRefusalJoinsLegacyBatchReply(t *testing.T) {
	stream := `[{"jsonrpc":"2.0","id":2,"method":"resources/list"},{"jsonrpc":"2.0","id":3,"method":"ping"}]` + "\n" +
		`[{"jsonrpc":"2.0","id":4,"method":"prompts/list"}]` + "\n" + `{"jsonrpc":"2.0","id":5,"method":"ping"}` + "\n"
	out := bytes.NewBuffer(nil)
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream)), nopWriteCloser{out})
	readRequest(t, connection, "ping", int64(3))
	if out.Len() != 0 {
		t.Fatalf("incomplete batch emitted a partial reply: %q", out.String())
	}
	id3, _ := jsonrpc.MakeID(float64(3))
	if err := connection.Write(context.Background(), &jsonrpc.Response{ID: id3, Result: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	var batch []json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &batch); err != nil || len(batch) != 2 {
		t.Fatalf("mixed batch was not answered as one two-element array: %q", out.String())
	}
	assertMethodNotFound(t, string(batch[0]), false, 2)
	if !strings.Contains(string(batch[1]), `"id":3`) || !strings.Contains(string(batch[1]), `"result":{}`) {
		t.Fatalf("batch lost the supported call's result: %q", batch[1])
	}
	out.Reset()
	readRequest(t, connection, "ping", int64(5))
	assertMethodNotFound(t, out.String(), true, 4)
}

func TestMCPStdioConnectionInboundResponseStaysFatal(t *testing.T) {
	stream := `{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream)), nopWriteCloser{bytes.NewBuffer(nil)})
	if _, err := connection.Read(context.Background()); !errors.Is(err, errMCPStdioUnsupportedMethod) {
		t.Fatalf("inbound response was not refused: %v", err)
	}
}

func TestMCPStdioCauseNamesBridgeRefusals(t *testing.T) {
	for err, want := range map[error]string{
		errMCPStdioUnsupportedMethod:                      "unsupported-message",
		fmt.Errorf("read: %w", errMCPStdioInvalidMessage): "invalid-message",
		errMCPStdioMessageLimit:                           "stdio-limit",
		errMCPStdioMessageCountLimit:                      "stdio-limit",
		errMCPStdioConcurrentRead:                         "concurrent-read",
		io.EOF:                                            "eof",
	} {
		if got := stdioCause(err); got != want {
			t.Fatalf("stdioCause(%v) = %q, want %q", err, got, want)
		}
	}
	if got := stdioCause(nil); got != "none" {
		t.Fatalf("stdioCause(nil) = %q", got)
	}
}

// Raw legacy initialize requests remain supported for every initialize-era
// protocol version. Unknown versions fall back to the newest legacy version;
// discovery is exercised separately because a modern discover establishes
// request-scoped state and must not be followed by initialize.
func TestMCPStdioSDKLegacyInitializeNegotiatesVersions(t *testing.T) {
	for _, tc := range []struct{ offered, want string }{
		{mcpProtocol20241105, mcpProtocol20241105},
		{mcpProtocol20250326, mcpProtocol20250326},
		{mcpProtocol20250618, mcpProtocol20250618},
		{mcpProtocol20251125, mcpProtocol20251125},
		{mcpProtocol20260728, mcpProtocol20251125},
		{"2020-01-01", mcpProtocol20251125},
		{"2099-01-01", mcpProtocol20251125},
	} {
		t.Run(tc.offered, func(t *testing.T) {
			in, out, cancel, runErr := startStdioSDKFixture(t, "stdio-legacy-fixture")
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"`+tc.offered+`","capabilities":{"roots":{}},"clientInfo":{"name":"legacy-client","version":"1"}}}`)
			initialized := sdkCallResults(t, readMCPLine(t, out), false, 2)
			if initialized[2]["protocolVersion"] != tc.want {
				t.Fatalf("offered %s negotiated %v, want %s", tc.offered, initialized[2]["protocolVersion"], tc.want)
			}
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
			if _, ok := sdkCallResults(t, readMCPLine(t, out), false, 3)[3]["tools"]; !ok {
				t.Fatal("tools/list after initialize carried no tools field")
			}
			cancel()
			if err := awaitSignal(t, runErr, "owned server run did not join"); !errors.Is(err, context.Canceled) {
				t.Fatalf("session did not survive until the orderly cancellation: %v", err)
			}
		})
	}
}

// The transport's protocol surface is a fixed five-version list, newest first.
func TestBridgeDeclaresExactSDKProtocolVersionSurface(t *testing.T) {
	want := []string{mcpProtocol20260728, mcpProtocol20251125, mcpProtocol20250618, mcpProtocol20250326, mcpProtocol20241105}
	got := supportedMCPProtocols()
	if !slices.Equal(got, want) {
		t.Fatalf("supported MCP versions = %v, want exactly %v", got, want)
	}
	if sdk := mcp.SupportedProtocolVersions(); !slices.Equal(sdk, want) {
		t.Fatalf("pinned SDK versions = %v, want exactly %v", sdk, want)
	}
	for _, version := range want {
		if !supportedMCPProtocol(version) {
			t.Errorf("bridge does not admit advertised protocol version %s", version)
		}
	}
	if negotiatedMCPVersion(mcpProtocol20260728) != mcpProtocol20251125 || negotiatedMCPVersion("") != mcpProtocol20251125 || negotiatedMCPVersion("2020-01-01") != mcpProtocol20251125 {
		t.Error("stateless, empty, or unknown version did not negotiate to the latest initialize-era version")
	}
}
