package apptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
)

type reverseFake struct {
	outcome appstorecrypto.ReverseTextOutcome
}

func (f *reverseFake) ReverseCopy(context.Context, string, string) appstorecrypto.ReverseTextOutcome {
	return f.outcome
}

func TestTextReverseStatusOnlyFailure(t *testing.T) {
	tests := []struct {
		name       string
		status     appstorecrypto.DeliveryStatus
		text       []byte
		wantStatus string
		wantText   *string
	}{
		{name: "unknown", status: appstorecrypto.DeliveryUnknown, text: []byte("synthetic-private-secret"), wantStatus: "unknown"},
		{name: "withheld", status: appstorecrypto.DeliveryWithheld, text: []byte("synthetic-private-secret"), wantStatus: "withheld"},
		{name: "empty received", status: appstorecrypto.DeliveryReceived, text: []byte{}, wantStatus: "received", wantText: new(string)},
		{name: "invalid UTF-8 received", status: appstorecrypto.DeliveryReceived, text: []byte{255}, wantStatus: "unknown"},
		{name: "NUL received", status: appstorecrypto.DeliveryReceived, text: []byte{0}, wantStatus: "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &reverseFake{outcome: appstorecrypto.ReverseTextOutcome{Status: tc.status, Text: tc.text}}
			server, err := ListenWithReverseTextAdapter(context.Background(), "approved", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
				t.Error("generic runner called")
				return 0, nil
			}, fake)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			boot := server.Bootstrap()
			client := transportClient(t, boot)
			infoStatus, infoBody := postInfo(t, client, boot, nil)
			if infoStatus != http.StatusOK {
				t.Fatalf("info status %d: %s", infoStatus, infoBody)
			}
			var info struct {
				Result struct {
					StructuredContent InfoOutput `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal(infoBody, &info); err != nil {
				t.Fatalf("decode info response: %v", err)
			}
			capabilities := info.Result.StructuredContent.Capabilities
			if len(capabilities) != 1 || capabilities[0] != "text_reverse_copy" {
				t.Fatalf("capabilities = %v, want [text_reverse_copy]", capabilities)
			}
			for _, name := range []string{"transport_read", "text_hydrate"} {
				status, body := postRPC(t, client, boot, name, map[string]any{}, nil)
				if status != http.StatusOK {
					t.Fatalf("%s status %d: %s", name, status, body)
				}
				var response struct {
					Error json.RawMessage `json:"error"`
				}
				if err := json.Unmarshal(body, &response); err != nil {
					t.Fatalf("decode %s response: %v", name, err)
				}
				if len(response.Error) == 0 || string(response.Error) == "null" {
					t.Fatalf("%s unexpectedly succeeded: %s", name, body)
				}
			}
			code, body := postRPC(t, client, boot, "text_reverse_copy", map[string]any{
				"operation_id": "AAECAwQFBgcICQoLDA0ODw",
				"file":         "/approved/config",
				"mode":         "reverse-copy-v1",
			}, nil)
			if code != http.StatusOK {
				t.Fatalf("HTTP status %d: %s", code, body)
			}
			if strings.Contains(string(body), "synthetic-private-secret") {
				t.Fatalf("response leaked text: %s", body)
			}

			var reply struct {
				Result struct {
					StructuredContent TextReverseCopyOutput `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal(body, &reply); err != nil {
				t.Fatal(err)
			}
			output := reply.Result.StructuredContent
			if output.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", output.Status, tc.wantStatus)
			}
			if tc.wantText == nil {
				if output.Text != nil {
					t.Errorf("text = %q, want nil", *output.Text)
				}
			} else if output.Text == nil || *output.Text != *tc.wantText {
				t.Errorf("text = %v, want %q", output.Text, *tc.wantText)
			}
			for _, b := range fake.outcome.Text {
				if b != 0 {
					t.Fatal("fake outcome text was not cleared")
				}
			}
		})
	}
}

type reverseContextFake struct {
	mu      sync.Mutex
	calls   map[string]int
	started chan struct{}
	aDone   chan struct{}
	bDone   chan struct{}
	cDone   chan struct{}
}

func (f *reverseContextFake) ReverseCopy(ctx context.Context, operationID, _ string) appstorecrypto.ReverseTextOutcome {
	f.mu.Lock()
	f.calls[operationID]++
	f.mu.Unlock()

	switch operationID {
	case "AAECAwQFBgcICQoLDA0ODw":
		close(f.started)
		<-ctx.Done()
		close(f.aDone)
		return appstorecrypto.ReverseTextOutcome{Status: appstorecrypto.DeliveryReceived, Text: []byte("unknownsecret bytes")}
	case "ERITFBUWFxgZGhscHR4fIA":
		defer close(f.bDone)
		if ctx.Err() != nil {
			return appstorecrypto.ReverseTextOutcome{Status: appstorecrypto.DeliveryWithheld}
		}
		return appstorecrypto.ReverseTextOutcome{Status: appstorecrypto.DeliveryReceived, Text: []byte("ordinary reference-only control")}
	case "ICEiIyQlJicoKSorLC0uLw":
		defer close(f.cDone)
		if ctx.Err() != nil {
			return appstorecrypto.ReverseTextOutcome{Status: appstorecrypto.DeliveryWithheld}
		}
		return appstorecrypto.ReverseTextOutcome{Status: appstorecrypto.DeliveryReceived, Text: []byte("ordinary reference-only control")}
	default:
		return appstorecrypto.ReverseTextOutcome{Status: appstorecrypto.DeliveryWithheld}
	}
}

func (f *reverseContextFake) count(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[id]
}

func TestReverseRequestCancellationIsPerRequest(t *testing.T) {
	flakediag.OnFailure(t, func() string {
		return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
	parent, cancelParent := context.WithTimeout(context.Background(), 15*time.Second)
	fake := &reverseContextFake{
		calls:   make(map[string]int),
		started: make(chan struct{}),
		aDone:   make(chan struct{}),
		bDone:   make(chan struct{}),
		cDone:   make(chan struct{}),
	}
	server, err := ListenWithReverseTextAdapter(parent, "approved", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		t.Error("generic runner must not be called")
		return 0, nil
	}, fake)
	if err != nil {
		cancelParent()
		t.Fatal(err)
	}
	client := transportClient(t, server.Bootstrap())
	resultA := make(chan struct {
		body []byte
		err  error
	}, 1)
	doneA := make(chan struct{})
	ctxA, cancelA := context.WithCancel(parent)
	defer func() {
		cancelA()
		cancelParent()
		server.Close()
		select {
		case <-doneA:
		case <-time.After(5 * time.Second):
			t.Error("request A goroutine did not finish")
		}
	}()
	go func() {
		defer close(doneA)
		body, err := reverseContextRequest(client, server.Bootstrap(), ctxA, "AAECAwQFBgcICQoLDA0ODw")
		resultA <- struct {
			body []byte
			err  error
		}{body, err}
	}()
	select {
	case <-fake.started:
	case <-time.After(5 * time.Second):
		t.Fatal("request A did not start")
	}

	bodyB, err := reverseContextRequest(client, server.Bootstrap(), parent, "ERITFBUWFxgZGhscHR4fIA")
	if err != nil {
		t.Fatalf("request B: %v", err)
	}
	assertReceivedReverseText(t, bodyB, "ordinary reference-only control")
	select {
	case <-fake.aDone:
		t.Fatal("request A canceled before its own context was canceled")
	default:
	}

	cancelA()
	select {
	case <-fake.aDone:
	case <-time.After(2 * time.Second):
		t.Fatal("request A backend did not observe cancellation")
	}
	select {
	case result := <-resultA:
		if result.err == nil {
			t.Error("canceled request A unexpectedly succeeded")
		}
		if len(result.body) != 0 {
			t.Errorf("canceled request A returned a body of %d bytes", len(result.body))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request A client did not finish")
	}
	if fake.count("AAECAwQFBgcICQoLDA0ODw") != 1 || fake.count("ERITFBUWFxgZGhscHR4fIA") != 1 {
		t.Fatal("unexpected A or B call count")
	}

	bodyC, err := reverseContextRequest(client, server.Bootstrap(), parent, "ICEiIyQlJicoKSorLC0uLw")
	if err != nil {
		t.Fatalf("request C: %v", err)
	}
	assertReceivedReverseText(t, bodyC, "ordinary reference-only control")
	select {
	case <-fake.cDone:
	case <-time.After(2 * time.Second):
		t.Fatal("request C did not complete")
	}
	if fake.count("ICEiIyQlJicoKSorLC0uLw") != 1 {
		t.Fatal("request C call count is not one")
	}
}

func assertReceivedReverseText(t *testing.T, body []byte, wantText string) {
	t.Helper()
	var reply struct {
		Result struct {
			StructuredContent TextReverseCopyOutput `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	output := reply.Result.StructuredContent
	if output.Status != "received" {
		t.Errorf("status = %q, want received", output.Status)
	}
	if output.Text == nil || *output.Text != wantText {
		t.Errorf("text = %v, want %q", output.Text, wantText)
	}
	if bytes.Contains(body, []byte("unknownsecret")) {
		t.Error("response contains secret text")
	}
}

func TestReverseRequestContextCancelAndDeadline(t *testing.T) {
	flakediag.OnFailure(t, func() string {
		return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
	t.Run("SDK cancellation", func(t *testing.T) {
		sdkCtx, cancelSDK := context.WithCancel(context.Background())
		requestCtx, cancelRequest := context.WithCancel(context.Background())
		defer cancelSDK()
		defer cancelRequest()
		combined, cleanup := reverseRequestContext(sdkCtx, requestCtx)
		defer cleanup()
		cancelSDK()
		select {
		case <-combined.Done():
		case <-time.After(time.Second):
			t.Fatal("SDK cancellation did not propagate")
		}
	})
	t.Run("request cancellation", func(t *testing.T) {
		sdkCtx, cancelSDK := context.WithCancel(context.Background())
		requestCtx, cancelRequest := context.WithCancel(context.Background())
		defer cancelSDK()
		defer cancelRequest()
		combined, cleanup := reverseRequestContext(sdkCtx, requestCtx)
		defer cleanup()
		cancelRequest()
		select {
		case <-combined.Done():
		case <-time.After(time.Second):
			t.Fatal("request cancellation did not propagate")
		}
	})
	t.Run("earlier request deadline", func(t *testing.T) {
		sdkDeadline := time.Now().Add(2 * time.Minute)
		requestDeadline := time.Now().Add(time.Minute)
		sdkCtx, cancelSDK := context.WithDeadline(context.Background(), sdkDeadline)
		requestCtx, cancelRequest := context.WithDeadline(context.Background(), requestDeadline)
		defer cancelSDK()
		defer cancelRequest()
		combined, cleanup := reverseRequestContext(sdkCtx, requestCtx)
		defer cleanup()
		got, ok := combined.Deadline()
		if !ok || !got.Equal(requestDeadline) {
			t.Fatalf("deadline = %v, want request deadline %v", got, requestDeadline)
		}
	})
	t.Run("earlier SDK deadline", func(t *testing.T) {
		sdkDeadline := time.Now().Add(time.Minute)
		requestDeadline := time.Now().Add(2 * time.Minute)
		sdkCtx, cancelSDK := context.WithDeadline(context.Background(), sdkDeadline)
		requestCtx, cancelRequest := context.WithDeadline(context.Background(), requestDeadline)
		defer cancelSDK()
		defer cancelRequest()
		combined, cleanup := reverseRequestContext(sdkCtx, requestCtx)
		defer cleanup()
		got, ok := combined.Deadline()
		if !ok || !got.Equal(sdkDeadline) {
			t.Fatalf("deadline = %v, want SDK deadline %v", got, sdkDeadline)
		}
	})
	t.Run("cleanup cancels context", func(t *testing.T) {
		sdkCtx, cancelSDK := context.WithCancel(context.Background())
		requestCtx, cancelRequest := context.WithCancel(context.Background())
		defer cancelSDK()
		defer cancelRequest()
		combined, cleanup := reverseRequestContext(sdkCtx, requestCtx)
		cleanup()
		if combined.Err() == nil {
			t.Fatal("cleanup did not cancel combined context")
		}
	})
}

func reverseContextRequest(client *http.Client, bootstrap Bootstrap, ctx context.Context, operationID string) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "text_reverse_copy",
			"arguments": map[string]string{
				"operation_id": operationID,
				"file":         "/approved/config",
				"mode":         "reverse-copy-v1",
			},
		},
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, bootstrap.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-06-18")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, io.ErrShortBuffer
	}
	if response.StatusCode != http.StatusOK {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
}

func (deadlineRecorder) SetWriteDeadline(time.Time) error {
	return nil
}

func TestServeBoundedReverseResponseOverflowReplacesBody(t *testing.T) {
	largeSentinel := bytes.Repeat([]byte("large-sentinel"), TextReverseResponseLimit/len("large-sentinel")+1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "safe-prefix")
		_, _ = w.Write(largeSentinel)
	})
	recorder := httptest.NewRecorder()
	serveBoundedReverseResponse(deadlineRecorder{recorder}, httptest.NewRequest(http.MethodPost, "/", nil), handler)

	if recorder.Body.String() != boundedReverseError {
		t.Fatalf("body = %q, want fixed error", recorder.Body.String())
	}
	if recorder.Body.Len() > TextReverseResponseLimit {
		t.Fatalf("body length = %d, exceeds limit", recorder.Body.Len())
	}
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("response status/content-type = %d/%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
}

func TestServeBoundedReverseResponseExactLimitAndImplicitStatus(t *testing.T) {
	body := bytes.Repeat([]byte("x"), TextReverseResponseLimit)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	recorder := httptest.NewRecorder()
	serveBoundedReverseResponse(deadlineRecorder{recorder}, httptest.NewRequest(http.MethodPost, "/", nil), handler)

	if recorder.Code != http.StatusOK || recorder.Body.Len() != TextReverseResponseLimit || !bytes.Equal(recorder.Body.Bytes(), body) {
		t.Fatalf("response status/length/body mismatch: status=%d length=%d", recorder.Code, recorder.Body.Len())
	}
	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content-type = %q", recorder.Header().Get("Content-Type"))
	}
}

func TestServeBoundedReverseResponseLatchesOverflowWriteError(t *testing.T) {
	writer := newBoundedReverseResponse()
	if n, err := writer.Write(bytes.Repeat([]byte("x"), TextReverseResponseLimit+1)); n != 0 || err != io.ErrShortWrite {
		t.Fatalf("first overflow Write() = (%d, %v), want (0, %v)", n, err, io.ErrShortWrite)
	}
	if n, err := writer.Write([]byte("later")); n != 0 || err != io.ErrShortWrite {
		t.Fatalf("later Write() = (%d, %v), want (0, %v)", n, err, io.ErrShortWrite)
	}
}

func TestServeBoundedReverseResponseCanceledContextReplacesBody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "safe-selected-text")
	})
	recorder := httptest.NewRecorder()
	serveBoundedReverseResponse(deadlineRecorder{recorder}, request, handler)

	if recorder.Body.String() != boundedReverseError || bytes.Contains(recorder.Body.Bytes(), []byte("safe-selected-text")) {
		t.Fatalf("canceled response body = %q, want fixed error", recorder.Body.String())
	}
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("response status/content-type = %d/%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
}

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

type pipeResponseWriter struct {
	conn    net.Conn
	header  http.Header
	entered chan struct{}
	once    sync.Once
	err     error
	n       int
}

func (w *pipeResponseWriter) Header() http.Header { return w.header }

func (w *pipeResponseWriter) WriteHeader(int) {}

func (w *pipeResponseWriter) SetWriteDeadline(deadline time.Time) error {
	return w.conn.SetWriteDeadline(deadline)
}

func (w *pipeResponseWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	w.n, w.err = w.conn.Write(p)
	return w.n, w.err
}

func (w *pipeResponseWriter) FlushError() error { return nil }

func newPipeResponseWriter(conn net.Conn) *pipeResponseWriter {
	return &pipeResponseWriter{
		conn:    conn,
		header:  make(http.Header),
		entered: make(chan struct{}),
	}
}

func TestServeBoundedReverseResponseCanceledBlockedWrite(t *testing.T) {
	flakediag.OnFailure(t, func() string {
		return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
	server, peer := net.Pipe()
	defer peer.Close()
	writer := newPipeResponseWriter(server)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	body := bytes.Repeat([]byte("x"), 64<<10)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveBoundedReverseResponse(writer, request, handler)
	}()

	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("response write did not begin")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled response write did not finish")
	}
	var netErr net.Error
	if writer.err == nil || !errors.As(writer.err, &netErr) || !netErr.Timeout() {
		t.Fatalf("write error = %v, want timeout net.Error", writer.err)
	}
	if writer.n != 0 {
		t.Fatalf("write count = %d, want 0", writer.n)
	}
}

func TestServeBoundedReverseResponseDeadlineBlockedWrite(t *testing.T) {
	flakediag.OnFailure(t, func() string {
		return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
	server, peer := net.Pipe()
	defer peer.Close()
	writer := newPipeResponseWriter(server)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	body := bytes.Repeat([]byte("x"), 64<<10)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveBoundedReverseResponse(writer, request, handler)
	}()

	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("response write did not begin")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deadline-bound response write did not finish")
	}
	var netErr net.Error
	if writer.err == nil || !errors.As(writer.err, &netErr) || !netErr.Timeout() {
		t.Fatalf("write error = %v, want timeout net.Error", writer.err)
	}
}

func TestServeBoundedReverseResponseCanceledBlockedFlush(t *testing.T) {
	flakediag.OnFailure(t, func() string {
		return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
	server, peer := net.Pipe()
	writer := &flushPipeResponseWriter{pipeResponseWriter: newPipeResponseWriter(server)}
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 64<<10))
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveBoundedReverseResponse(writer, request, handler)
	}()
	defer func() {
		cancel()
		_ = server.Close()
		_ = peer.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("response server did not stop")
		}
	}()

	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("flush write did not begin")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled response flush did not finish")
	}
	var netErr net.Error
	if writer.err == nil || !errors.As(writer.err, &netErr) || !netErr.Timeout() {
		t.Fatalf("flush error = %v, want timeout net.Error", writer.err)
	}
	if writer.n != 0 {
		t.Fatalf("flush write count = %d, want 0", writer.n)
	}
}

type flushPipeResponseWriter struct {
	*pipeResponseWriter
	buffer []byte
}

func (w *flushPipeResponseWriter) Write(p []byte) (int, error) {
	w.buffer = append(w.buffer, p...)
	return len(p), nil
}

func (w *flushPipeResponseWriter) FlushError() error {
	_, err := w.pipeResponseWriter.Write(w.buffer)
	return err
}

func TestServeBoundedReverseResponseHealthyPipeWrite(t *testing.T) {
	flakediag.OnFailure(t, func() string {
		return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	writer := newPipeResponseWriter(server)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	body := bytes.Repeat([]byte("healthy response"), (64<<10)/len("healthy response"))
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	type readResult struct {
		body []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		got := make([]byte, len(body))
		_, err := io.ReadFull(peer, got)
		readDone <- readResult{body: got, err: err}
	}()

	serveBoundedReverseResponse(writer, request, handler)
	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatalf("read response: %v", result.err)
		}
		if !bytes.Equal(result.body, body) {
			t.Fatal("received response differs from handler body")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not finish reading response")
	}
	if writer.err != nil || writer.n != len(body) {
		t.Fatalf("write = (%d, %v), want (%d, nil)", writer.n, writer.err, len(body))
	}
}
