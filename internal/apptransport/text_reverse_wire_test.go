package apptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
)

type reverseWireFake struct {
	calls   atomic.Int32
	outcome appstorecrypto.ReverseTextOutcome
}

func (f *reverseWireFake) ReverseCopy(context.Context, string, string) appstorecrypto.ReverseTextOutcome {
	f.calls.Add(1)
	return f.outcome
}

func postReverseWire(t *testing.T, bootstrap Bootstrap) (int, []byte) {
	t.Helper()
	requestBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "text_reverse_copy",
			"arguments": map[string]any{
				"operation_id": "op",
				"file":         "approved.txt",
				"mode":         "reverse-copy-v1",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, bootstrap.Endpoint, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-06-18")

	client := transportClient(t, bootstrap)
	client.Timeout = 10 * time.Second
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, TextReverseResponseLimit+1))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}

func reverseWireRunner(ctx context.Context, operationID, file string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return 0, nil
}

func TestReverseTextWireLargeValidUTF8(t *testing.T) {
	const inputLimit = 1 << 20
	controls := make([]byte, 0, 40)
	for b := byte(1); b < 32; b++ {
		controls = append(controls, b)
	}
	controls = append(controls, '"', '\\', '<', '>', '&')
	pattern := string(controls) + "\u2028\u2029"
	var worst strings.Builder
	for worst.Len()+len(pattern) <= inputLimit {
		worst.WriteString(pattern)
	}
	cases := []struct {
		name string
		text string
	}{
		{name: "worst-case escaping", text: worst.String()},
		{name: "worst-case exact limit", text: strings.Repeat("\x01", inputLimit)},
		{name: "control-byte escaping", text: strings.Repeat(string(controls[:len(controls)-7]), inputLimit/(len(controls)-7))},
		{name: "unicode and mixed", text: strings.Repeat("plain-🙂-\u2028-\u2029-<>&-\\-\"", inputLimit/len("plain-🙂-\u2028-\u2029-<>&-\\-\""))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.text) > inputLimit {
				t.Fatalf("input length %d exceeds limit", len(tc.text))
			}
			fake := &reverseWireFake{
				outcome: appstorecrypto.ReverseTextOutcome{
					Status: appstorecrypto.DeliveryReceived,
					Text:   []byte(tc.text),
				},
			}
			server, err := ListenWithReverseTextAdapter(context.Background(), "approved", reverseWireRunner, fake)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			status, raw := postReverseWire(t, server.Bootstrap())
			if len(raw) > TextReverseResponseLimit {
				t.Fatalf("response length %d exceeds limit %d (HTTP %d)", len(raw), TextReverseResponseLimit, status)
			}
			if status != http.StatusOK {
				t.Fatalf("HTTP status %d, response length %d", status, len(raw))
			}

			var reply struct {
				Result struct {
					StructuredContent TextReverseCopyOutput `json:"structuredContent"`
					Content           []struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"content"`
				} `json:"result"`
			}
			if err := json.Unmarshal(raw, &reply); err != nil {
				t.Fatalf("decode response length %d: %v", len(raw), err)
			}
			output := reply.Result.StructuredContent
			if output.Status != "received" || output.Text == nil || *output.Text != tc.text {
				actualLength := 0
				if output.Text != nil {
					actualLength = len(*output.Text)
				}
				t.Fatalf("structured result mismatch: status=%q hasText=%v expectedLength=%d actualLength=%d responseLength=%d", output.Status, output.Text != nil, len(tc.text), actualLength, len(raw))
			}
			textItems := 0
			for _, item := range reply.Result.Content {
				if item.Type != "text" {
					continue
				}
				textItems++
				var content TextReverseCopyOutput
				if err := json.Unmarshal([]byte(item.Text), &content); err != nil {
					t.Fatalf("decode content text: %v", err)
				}
				if content.Status != output.Status || content.Text == nil || *content.Text != tc.text {
					t.Fatalf("content text differs from structured result (content length %d)", len(item.Text))
				}
			}
			if textItems == 0 {
				t.Fatal("response contains no text content item")
			}
			if fake.calls.Load() != 1 {
				t.Fatalf("backend calls %d, want 1", fake.calls.Load())
			}
			for _, b := range fake.outcome.Text {
				if b != 0 {
					t.Fatal("backend output was not cleared")
				}
			}
		})
	}
}

func TestReverseTextWireOversizeIsUnknown(t *testing.T) {
	const inputLimit = 1 << 20
	fake := &reverseWireFake{
		outcome: appstorecrypto.ReverseTextOutcome{
			Status: appstorecrypto.DeliveryReceived,
			Text:   bytes.Repeat([]byte{'x'}, inputLimit+1),
		},
	}
	server, err := ListenWithReverseTextAdapter(context.Background(), "approved", reverseWireRunner, fake)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	status, raw := postReverseWire(t, server.Bootstrap())
	if status != http.StatusOK {
		t.Fatalf("HTTP status %d, response length %d", status, len(raw))
	}
	var reply struct {
		Result struct {
			StructuredContent TextReverseCopyOutput `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatalf("decode response length %d: %v", len(raw), err)
	}
	if reply.Result.StructuredContent.Status != "unknown" || reply.Result.StructuredContent.Text != nil {
		t.Fatalf("oversize output did not map to unknown without text (HTTP %d, response length %d)", status, len(raw))
	}
	if bytes.Contains(raw, []byte("xxxxxxxxxxxxxxxxxxxxxxxx")) {
		t.Fatalf("oversize output sentinel present (HTTP %d, response length %d)", status, len(raw))
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("backend calls %d, want 1", fake.calls.Load())
	}
}
