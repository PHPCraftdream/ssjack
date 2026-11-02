package apptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
)

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
