package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestMCPStdioRejectsModernBatchesBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame string
	}{
		{
			name:  "latest modern metadata without initialize",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}]`,
		},
		{
			name:  "mixed legacy and latest modern metadata",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26"}}},{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}]`,
		},
		{
			name:  "modern metadata without initialize",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}}]`,
		},
		{
			name:  "mixed legacy and modern metadata",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26"}}},{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}}]`,
		},
		{
			name:  "newer initialize offer",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}},{"jsonrpc":"2.0","id":2,"method":"ping"}]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := bytes.NewBuffer(nil)
			connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(tc.frame+"\n")), nopWriteCloser{out})
			if _, err := connection.Read(context.Background()); !errors.Is(err, errMCPStdioBatchUnsupported) {
				t.Fatalf("modern batch error = %v, want errMCPStdioBatchUnsupported", err)
			}
			if out.Len() != 0 {
				t.Fatalf("refused modern batch wrote to stdout: %q", out.String())
			}
			if connection.protocolVersion != "" {
				t.Fatalf("refused batch changed the legacy protocol tracker: %q", connection.protocolVersion)
			}
		})
	}
}

func TestMCPStdioRejectsMalformedBatchesBeforeTracking(t *testing.T) {
	cases := []struct {
		name   string
		method string
		params string
	}{
		{
			name:   "wrong typed top-level version with modern metadata",
			method: "tools/list",
			params: `{"protocolVersion":false,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`,
		},
		{name: "metadata array", method: "ping", params: `{"_meta":[]}`},
		{name: "metadata string", method: "ping", params: `{"_meta":"bad"}`},
		{name: "metadata boolean", method: "ping", params: `{"_meta":true}`},
		{name: "metadata null", method: "ping", params: `{"_meta":null}`},
		{name: "params array", method: "ping", params: `[]`},
		{name: "params boolean", method: "ping", params: `false`},
		{name: "params null", method: "ping", params: `null`},
		{name: "params string", method: "ping", params: `"bad"`},
		{name: "modern initialize offer", method: "initialize", params: `{"protocolVersion":"2026-07-28"}`},
		{name: "future initialize offer", method: "initialize", params: `{"protocolVersion":"2099-01-01"}`},
		{name: "initialize at modern cutoff", method: "initialize", params: `{"protocolVersion":"2025-06-18"}`},
	}
	for _, value := range []string{"", "nonsense", "2025-99-99", "2025-03-26T00:00:00Z"} {
		cases = append(cases,
			struct {
				name   string
				method string
				params string
			}{name: "malformed top-level date " + value, method: "tools/list", params: `{"protocolVersion":` + mustJSONTestString(t, value) + `}`},
			struct {
				name   string
				method string
				params string
			}{name: "malformed metadata date " + value, method: "ping", params: `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + mustJSONTestString(t, value) + `}}`},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := `[ {"jsonrpc":"2.0","id":1,"method":` + mustJSONTestString(t, tc.method) + `,"params":` + tc.params + `} ]` + "\n"
			out := bytes.NewBuffer(nil)
			connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(frame)), nopWriteCloser{out})
			if _, err := connection.Read(context.Background()); !errors.Is(err, errMCPStdioBatchUnsupported) {
				t.Fatalf("malformed batch error = %v, want errMCPStdioBatchUnsupported", err)
			}
			if out.Len() != 0 {
				t.Fatalf("refused malformed batch wrote to stdout: %q", out.String())
			}
			if connection.protocolVersion != "" || len(connection.batches) != 0 {
				t.Fatalf("refused malformed batch changed legacy tracking: version=%q batches=%d", connection.protocolVersion, len(connection.batches))
			}
		})
	}
}

func TestBatchHasModernProtocolVersionRejectsMalformedRawParams(t *testing.T) {
	request := &jsonrpc.Request{Method: "ping", Params: json.RawMessage(`{"malformed":`)}
	if !batchHasModernProtocolVersion([]jsonrpc.Message{request}) {
		t.Fatal("malformed raw params were not conservatively rejected")
	}
}

func TestMCPStdioKeepsLegacyBatchesSupported(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		params string
	}{
		{name: "legacy ping without params", method: "ping"},
		{name: "earliest initialize", method: "initialize", params: `{"protocolVersion":"2024-11-05"}`},
		{name: "next initialize", method: "initialize", params: `{"protocolVersion":"2025-03-26"}`},
		{name: "legacy metadata", method: "ping", params: `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := ""
			if tc.params != "" {
				params = `,"params":` + tc.params
			}
			frame := `[ {"jsonrpc":"2.0","id":1,"method":` + mustJSONTestString(t, tc.method) + params + `} ]` + "\n"
			connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(frame)), nopWriteCloser{bytes.NewBuffer(nil)})
			if _, err := connection.Read(context.Background()); err != nil {
				t.Fatalf("legacy batch was refused: %v", err)
			}
			if len(connection.batches) != 1 {
				t.Fatalf("legacy batch tracked %d IDs, want 1", len(connection.batches))
			}
		})
	}
}

func mustJSONTestString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestMCPStdioModernRequestDoesNotChangeLegacyBatchTracking(t *testing.T) {
	modern := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	var stream strings.Builder
	stream.WriteString(modern + "\n")
	for i, version := range []string{mcpProtocol20241105, mcpProtocol20250326} {
		firstID, secondID := 10+int64(i)*10, 11+int64(i)*10
		fmt.Fprintf(&stream,
			`[{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}},{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}}]`+"\n",
			firstID, version, secondID, version)
	}

	out := bytes.NewBuffer(nil)
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream.String())), nopWriteCloser{out})
	readMCPCall := func(wantID int64) {
		t.Helper()
		message, err := connection.Read(context.Background())
		if err != nil {
			t.Fatalf("read call %d: %v", wantID, err)
		}
		request, ok := message.(*jsonrpc.Request)
		if !ok || request.Method != "ping" || request.ID.Raw() != wantID {
			t.Fatalf("read call = %#v, want ping id %d", message, wantID)
		}
	}

	readMCPCall(1)
	if connection.protocolVersion != "" {
		t.Fatalf("modern per-request metadata changed the legacy tracker: %q", connection.protocolVersion)
	}
	for i, version := range []string{mcpProtocol20241105, mcpProtocol20250326} {
		firstID, secondID := 10+int64(i)*10, 11+int64(i)*10
		readMCPCall(firstID)
		readMCPCall(secondID)
		if connection.protocolVersion != "" {
			t.Fatalf("legacy batch %s changed the initialize tracker: %q", version, connection.protocolVersion)
		}
		for _, id := range []int64{firstID, secondID} {
			jsonID, err := jsonrpc.MakeID(float64(id))
			if err != nil {
				t.Fatal(err)
			}
			if err := connection.Write(context.Background(), &jsonrpc.Response{ID: jsonID, Result: json.RawMessage(`{"ok":true}`)}); err != nil {
				t.Fatalf("write batch response %d: %v", id, err)
			}
		}
		var responses []struct {
			ID     int64           `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &responses); err != nil {
			t.Fatalf("legacy %s batch response was not an array: %q (%v)", version, out.String(), err)
		}
		if len(responses) != 2 || responses[0].ID != firstID || responses[1].ID != secondID || len(responses[0].Result) == 0 || len(responses[1].Result) == 0 || len(responses[0].Error) != 0 || len(responses[1].Error) != 0 {
			t.Fatalf("legacy %s batch responses were not aggregated in request order: %#v", version, responses)
		}
		out.Reset()
	}
}

func TestMCPStdioModernMetadataKeepsFrameDepthAndDuplicateBounds(t *testing.T) {
	const modernMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
	base := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + modernMeta + `}}`)
	for _, size := range []int{maxMCPStdioMessage, maxMCPStdioMessage + 1} {
		frame := append(append([]byte(nil), base...), bytes.Repeat([]byte{' '}, size-len(base))...)
		input := &fragmentedMCPInput{data: frame, n: 137}
		connection := newMCPStdioTransport(input, nopWriteCloser{bytes.NewBuffer(nil)})
		message, err := connection.Read(context.Background())
		if size == maxMCPStdioMessage {
			request, ok := message.(*jsonrpc.Request)
			if err != nil || !ok || request.Method != "ping" {
				t.Fatalf("fragmented modern-metadata frame at exact byte bound was refused: %#v, %v", message, err)
			}
		} else if !errors.Is(err, errMCPStdioMessageLimit) {
			t.Fatalf("fragmented modern-metadata frame over byte bound error = %v", err)
		}
	}

	deep := `{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"nested":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}}` + "\n"
	deepReader := newBoundedMCPStdioReader(&fragmentedMCPInput{data: []byte(deep), n: 11})
	if n, err := deepReader.Read(make([]byte, maxMCPStdioMessage+1)); n != 0 || !errors.Is(err, errMCPStdioInvalidMessage) {
		t.Fatalf("over-depth modern metadata frame yielded %d bytes with error %v", n, err)
	}

	duplicate := `{"jsonrpc":"2.0","id":3,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2024-11-05","io.modelcontextprotocol/protocolVersion":"2025-03-26"}}}` + "\n"
	duplicateReader := newBoundedMCPStdioReader(&fragmentedMCPInput{data: []byte(duplicate), n: 7})
	if n, err := duplicateReader.Read(make([]byte, maxMCPStdioMessage+1)); n != 0 || !errors.Is(err, errMCPStdioInvalidMessage) {
		t.Fatalf("duplicate modern metadata version yielded %d bytes with error %v", n, err)
	}
}

func TestMCPStdioUnsupportedMetaRefusalsSpendMessageBound(t *testing.T) {
	var stream strings.Builder
	for id := 1; id <= maxMCPStdioMessages; id++ {
		fmt.Fprintf(&stream, `{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}}`+"\n", id)
	}
	stream.WriteString(`{"jsonrpc":"2.0","id":5000,"method":"ping"}` + "\n")
	out := bytes.NewBuffer(nil)
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream.String())), nopWriteCloser{out})
	if _, err := connection.Read(context.Background()); !errors.Is(err, errMCPStdioMessageCountLimit) {
		t.Fatalf("message after %d unsupported-version refusals returned %v", maxMCPStdioMessages, err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != maxMCPStdioMessages {
		t.Fatalf("got %d unsupported-version responses, want %d", len(lines), maxMCPStdioMessages)
	}
	for i, line := range lines {
		var response struct {
			ID    int64 `json:"id"`
			Error struct {
				Code int64 `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &response); err != nil || response.ID != int64(i+1) || response.Error.Code != -32022 {
			t.Fatalf("unsupported-version response %d was not the raw -32022 refusal: %q (%v)", i+1, line, err)
		}
	}

	wrapped := fmt.Errorf("batch unsupported in 2099-01-01 and later: %w", errMCPStdioBatchUnsupported)
	if cause := stdioCause(wrapped); cause != "unsupported-batch" || strings.Contains(cause, "2099-01-01") {
		t.Fatalf("stdioCause leaked an arbitrary protocol version: %q", cause)
	}
}
