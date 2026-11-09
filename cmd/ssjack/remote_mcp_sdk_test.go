package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sdkCallResults decodes one reply line with the pinned SDK decoder, asserts
// the wire container and each response envelope (exact ids, no error field,
// object result), and returns the result objects keyed by numeric id.
func sdkCallResults(t *testing.T, line string, wantArray bool, wantIDs ...int64) map[int64]map[string]any {
	t.Helper()
	trimmed := bytes.TrimSpace([]byte(strings.TrimSuffix(line, "\n")))
	if len(trimmed) == 0 || (trimmed[0] == '[') != wantArray {
		t.Fatalf("reply container mismatch: want array=%v got %s", wantArray, trimmed)
	}
	var raws []json.RawMessage
	if wantArray {
		if err := json.Unmarshal(trimmed, &raws); err != nil {
			t.Fatalf("array reply line did not decode: %s", trimmed)
		}
	} else {
		raws = []json.RawMessage{trimmed}
	}
	if len(raws) != len(wantIDs) {
		t.Fatalf("reply carried %d responses, want %d: %s", len(raws), len(wantIDs), trimmed)
	}
	results := make(map[int64]map[string]any, len(wantIDs))
	for _, raw := range raws {
		message, err := jsonrpc.DecodeMessage(raw)
		if err != nil {
			t.Fatalf("reply message did not decode: %v", err)
		}
		response, ok := message.(*jsonrpc.Response)
		if !ok {
			t.Fatalf("reply carried a non-response message: %#v", message)
		}
		gotID, ok := response.ID.Raw().(int64)
		if !ok {
			t.Fatalf("response id %v is %T, want an int64", response.ID.Raw(), response.ID.Raw())
		}
		if _, dup := results[gotID]; dup {
			t.Fatalf("reply carried duplicate id %v", gotID)
		}
		var envelope struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("response envelope did not decode: %v", err)
		}
		if len(envelope.Error) != 0 {
			t.Fatalf("response for id %v carried an error field: %s", gotID, envelope.Error)
		}
		var result map[string]any
		if err := json.Unmarshal(envelope.Result, &result); err != nil {
			t.Fatalf("result for id %v was not a JSON object: %s", gotID, envelope.Result)
		}
		if result == nil {
			t.Fatalf("result for id %v was JSON null, want an object", gotID)
		}
		results[gotID] = result
	}
	for _, want := range wantIDs {
		if _, ok := results[want]; !ok {
			t.Fatalf("reply lost the response for id %d: %#v", want, results)
		}
	}
	return results
}

// joinExited bounded-asserts one worker exit; cleanup-safe because it uses
// t.Error instead of t.Fatal, so every joined worker is reported.
func joinExited(t *testing.T, exited <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Error(message)
	}
}

func writeMCPFrame(t *testing.T, w io.WriteCloser, frame string) {
	t.Helper()
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		_, err := io.WriteString(w, frame+"\n")
		done <- err
	}()
	select {
	case err := <-done:
		awaitSignal(t, exited, "frame write worker did not exit")
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		w.Close()
		awaitSignal(t, exited, "frame write worker did not exit after its writer was released")
		t.Fatal("bounded frame write blocked")
	}
	awaitSignal(t, exited, "frame write worker did not exit")
}

// readMCPLine reads one newline-terminated line byte-by-byte without
// prefetching, so no bytes beyond the line are consumed from r.
func readMCPLine(t *testing.T, r io.ReadCloser) string {
	t.Helper()
	done := make(chan string, 1)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		var line []byte
		one := make([]byte, 1)
		for {
			n, err := r.Read(one)
			line = append(line, one[:n]...)
			if n > 0 && line[len(line)-1] == '\n' {
				done <- string(line)
				return
			}
			if err != nil {
				done <- string(line)
				return
			}
		}
	}()
	select {
	case text := <-done:
		awaitSignal(t, exited, "reply read worker did not exit")
		return text
	case <-time.After(2 * time.Second):
		r.Close()
		awaitSignal(t, exited, "reply read worker did not exit after its reader was released")
		t.Fatal("owned reply line did not arrive")
	}
	return ""
}

// awaitSignal joins one owned worker or gate with the shared one-second budget.
func awaitSignal[T any](t *testing.T, signal <-chan T, message string) T {
	t.Helper()
	select {
	case value := <-signal:
		return value
	case <-time.After(time.Second):
		t.Fatal(message)
	}
	var zero T
	return zero
}

// startStdioSDKFixture runs the real pinned SDK server over owned pipes and
// registers a cleanup that cancels orderly, releases every pipe endpoint, and
// joins the server goroutine bounded.
func startStdioSDKFixture(t *testing.T, name string) (io.WriteCloser, io.ReadCloser, context.CancelFunc, <-chan error) {
	serverIn, serverInWriter := io.Pipe()
	clientOut, clientOutWriter := io.Pipe()
	server := mcp.NewServer(&mcp.Implementation{Name: name, Version: "1"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	runErr, runDone := make(chan error, 1), make(chan struct{})
	go func() { runErr <- server.Run(ctx, newMCPStdioTransport(serverIn, clientOutWriter)); close(runDone) }()
	t.Cleanup(func() {
		cancel()
		clientOutWriter.Close()
		clientOut.Close()
		serverInWriter.Close()
		select {
		case <-runDone:
		case <-time.After(time.Second):
			t.Error("owned server goroutine did not join")
		}
	})
	return serverInWriter, clientOut, cancel, runErr
}

func TestMCPStdioNegotiationRefusesBatchAfter20250618(t *testing.T) {
	in, out, _, runErr := startStdioSDKFixture(t, "stdio-negotiation-fixture")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	line := readMCPLine(t, out)
	if !strings.Contains(line, `"id":1`) || !strings.Contains(line, `"protocolVersion":"`+mcpProtocol20250618+`"`) {
		t.Fatalf("initialize response lost the negotiated version: %q", line)
	}
	writeMCPFrame(t, in, `[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`)
	select {
	case err := <-runErr:
		if err == nil || !strings.Contains(err.Error(), "batching") {
			t.Fatalf("post-2025-06-18 batch was not refused by the negotiated version: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("negotiated batch refusal did not terminate the SDK server run")
	}
}

func TestMCPStdioSDKAnswersLegacyBatchWithSingleArray(t *testing.T) {
	in, out, cancel, runErr := startStdioSDKFixture(t, "stdio-batch-fixture")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	line := readMCPLine(t, out)
	if !strings.Contains(line, `"id":1`) || !strings.Contains(line, `"protocolVersion":"2024-11-05"`) {
		t.Fatalf("initialize response lost its negotiated legacy version: %q", line)
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	writeMCPFrame(t, in, `[{"jsonrpc":"2.0","id":2,"method":"ping"},{"jsonrpc":"2.0","id":3,"method":"tools/list"}]`)
	results := sdkCallResults(t, readMCPLine(t, out), true, 2, 3)
	if len(results[2]) != 0 {
		t.Fatalf("ping result was not the empty object: %#v", results[2])
	}
	tools, ok := results[3]["tools"].([]any)
	if !ok || len(tools) != 0 {
		t.Fatalf("tools/list result did not carry an empty tools array: %#v", results[3]["tools"])
	}
	cancel()
	if err := awaitSignal(t, runErr, "owned server run did not join"); !errors.Is(err, context.Canceled) {
		t.Fatalf("owned server run did not end with the orderly cancellation: %v", err)
	}
}

func TestMCPStdioSDKMixedBatchEmitsCallResponseOnly(t *testing.T) {
	in, out, cancel, runErr := startStdioSDKFixture(t, "stdio-mixed-fixture")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	line := readMCPLine(t, out)
	if !strings.Contains(line, `"id":1`) || !strings.Contains(line, `"protocolVersion":"2024-11-05"`) {
		t.Fatalf("initialize response lost its negotiated legacy version: %q", line)
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	writeMCPFrame(t, in, `[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`)
	results := sdkCallResults(t, readMCPLine(t, out), true, 2)
	if len(results[2]) != 0 {
		t.Fatalf("mixed legacy batch ping result was not the empty object: %#v", results[2])
	}
	cancel()
	if err := awaitSignal(t, runErr, "owned server run did not join"); !errors.Is(err, context.Canceled) {
		t.Fatalf("owned server run did not end with the orderly cancellation: %v", err)
	}
}

func TestMCPStdioSDKNotificationOnlyBatchEmitsNoReply(t *testing.T) {
	in, out, cancel, runErr := startStdioSDKFixture(t, "stdio-quiet-fixture")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	line := readMCPLine(t, out)
	if !strings.Contains(line, `"id":1`) || !strings.Contains(line, `"protocolVersion":"2024-11-05"`) {
		t.Fatalf("initialize response lost its negotiated legacy version: %q", line)
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	writeMCPFrame(t, in, `[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","method":"ping"}]`)
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":4,"method":"ping"}`)
	results := sdkCallResults(t, readMCPLine(t, out), false, 4)
	if len(results[4]) != 0 {
		t.Fatalf("id 4 ping result was not the empty object: %#v", results[4])
	}
	cancel()
	if err := awaitSignal(t, runErr, "owned server run did not join"); !errors.Is(err, context.Canceled) {
		t.Fatalf("owned server run did not end with the orderly cancellation: %v", err)
	}
}

func TestMCPStdioConnectionBuffersIncompleteBatchUnderClose(t *testing.T) {
	stream := []byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]` + "\n")
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(stream)), &scriptedWriter{})
	if _, err := connection.Read(context.Background()); err != nil {
		t.Fatalf("two-call legacy batch head did not decode: %v", err)
	}
	firstResponse, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	if err != nil {
		t.Fatalf("first tracked response did not decode: %v", err)
	}
	if err := connection.Write(context.Background(), firstResponse); err != nil {
		t.Fatalf("incomplete tracked response was not buffered: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("owned close failed: %v", err)
	}
	secondResponse, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`))
	if err != nil {
		t.Fatalf("second tracked response did not decode: %v", err)
	}
	if err := connection.Write(context.Background(), secondResponse); !errors.Is(err, errMCPStdioWriterClosed) {
		t.Fatalf("tracked response after close lost the fixed refusal: %v", err)
	}
	connection.batchMu.Lock()
	tracked := len(connection.batches)
	connection.batchMu.Unlock()
	if tracked != 1 {
		t.Fatalf("incomplete buffered batch was dropped after close: %d entries", tracked)
	}
}
