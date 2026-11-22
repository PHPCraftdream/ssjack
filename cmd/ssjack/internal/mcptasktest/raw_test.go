package mcptasktest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
)

// rawError is the JSON-RPC error object of one raw reply.
type rawError struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

// rawResponse is the envelope of one raw reply line.
type rawResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rawError       `json:"error"`
}

// rawReader forwards the child's stdout lines to one channel from one reader
// goroutine; no other goroutine reads the child's stdout.
type rawReader struct {
	lines chan string
}

// newRawReader starts the only reader of the child's stdout.
func newRawReader(stream io.Reader) *rawReader {
	reader := &rawReader{lines: make(chan string, 16)}
	go func() {
		defer close(reader.lines)
		scanner := bufio.NewScanner(stream)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			reader.lines <- scanner.Text()
		}
	}()
	return reader
}

// next waits for the next reply line without a bare sleep and fails the test
// when none arrives within the budget.
func (r *rawReader) next(t *testing.T, ctx context.Context, what string) string {
	t.Helper()
	var line string
	done, desc, waitErr := flakediag.WaitForDesc(t, what, 30*time.Second, func() (string, bool, error) {
		select {
		case <-ctx.Done():
			return "test context done", false, ctx.Err()
		case next, ok := <-r.lines:
			if !ok {
				return "the child closed its stdout", false, errors.New("the mcp task bridge child closed stdout")
			}
			line = next
			return "reply arrived", true, nil
		default:
			return "no reply yet", false, nil
		}
	})
	if !done {
		t.Fatalf("%s did not arrive: %s (%v)", what, desc, waitErr)
	}
	return line
}

// TestMCPTaskMethodsAreRefusedOnALegacyConnection drives raw JSON-RPC over the
// launched bridge: a legacy connection learns about the extension and is still
// refused the three task methods.
func TestMCPTaskMethodsAreRefusedOnALegacyConnection(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), bridgeTestBudget)
	defer cancel()

	keeper := &launchKeeper{}
	stdin, stdout, process := startRawBridge(t, ctx, keeper.Handle)
	t.Cleanup(func() { _ = stdout.Close() })
	reader := newRawReader(stdout)

	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+legacyVersion+`","capabilities":{},"clientInfo":{"name":"legacy-probe","version":"1"}}}`)
	requireLegacyInitialize(t, reader.next(t, ctx, "initialize reply"))

	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"taskId":"`+strings.Repeat("ab", 32)+`"}}`)
	requireMethodNotFound(t, "tasks/get", reader.next(t, ctx, "tasks/get reply"))

	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":4,"method":"tasks/update","params":{"taskId":"`+strings.Repeat("ab", 32)+`","inputResponses":{}}}`)
	requireMethodNotFound(t, "tasks/update", reader.next(t, ctx, "tasks/update reply"))

	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":5,"method":"tasks/cancel","params":{"taskId":"`+strings.Repeat("ab", 32)+`"}}`)
	requireMethodNotFound(t, "tasks/cancel", reader.next(t, ctx, "tasks/cancel reply"))

	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":6,"method":"server/discover"}`)
	requireMethodNotFound(t, "server/discover", reader.next(t, ctx, "server/discover reply"))

	if err := stdin.Close(); err != nil {
		t.Fatalf("could not close the child's stdin: %v", err)
	}
	if err := process.waitBounded(t, bridgeExitBudget); err != nil {
		t.Fatalf("the legacy bridge child did not exit cleanly: %v", err)
	}
}

// requireLegacyInitialize checks the modern extension advertisement of the
// legacy handshake.
func requireLegacyInitialize(t *testing.T, line string) {
	t.Helper()
	response := decodeRawResponse(t, "initialize", line)
	if response.Error != nil {
		t.Fatalf("initialize was refused: %q", line)
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Extensions map[string]any `json:"extensions"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("the initialize result did not decode: %s (%v)", response.Result, err)
	}
	if result.ProtocolVersion < legacyVersion {
		t.Fatalf("initialize negotiated %q, want %q or newer", result.ProtocolVersion, legacyVersion)
	}
	if _, declared := result.Capabilities.Extensions[taskExtension]; !declared {
		t.Fatalf("initialize did not advertise %q: %s", taskExtension, response.Result)
	}
}

// requireMethodNotFound checks one -32601 refusal with no result.
func requireMethodNotFound(t *testing.T, method, line string) {
	t.Helper()
	response := decodeRawResponse(t, method, line)
	if response.Error == nil || response.Error.Code != -32601 {
		t.Fatalf("%s was not refused with -32601: %q", method, line)
	}
	if len(bytes.TrimSpace(response.Result)) != 0 {
		t.Fatalf("%s carried a result next to its error: %q", method, line)
	}
}

// decodeRawResponse decodes one raw reply line that must carry exactly one of
// a result and an error.
func decodeRawResponse(t *testing.T, what, line string) rawResponse {
	t.Helper()
	if strings.TrimSpace(line) == "" {
		t.Fatalf("%s: the reply line was empty", what)
	}
	var response rawResponse
	if err := json.Unmarshal([]byte(line), &response); err != nil {
		t.Fatalf("%s: the reply line did not decode: %q (%v)", what, line, err)
	}
	if response.Error == nil && len(bytes.TrimSpace(response.Result)) == 0 {
		t.Fatalf("%s: the reply carried neither a result nor an error: %q", what, line)
	}
	return response
}

// writeRawFrame writes one newline-terminated JSON-RPC frame.
func writeRawFrame(t *testing.T, writer io.Writer, frame string) {
	t.Helper()
	if _, err := io.WriteString(writer, frame+"\n"); err != nil {
		t.Fatalf("could not write a raw MCP frame: %v", err)
	}
}
