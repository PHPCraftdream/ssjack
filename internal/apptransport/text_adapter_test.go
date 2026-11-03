package apptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
)

type textHydratorFake struct {
	mu          sync.Mutex
	calls       int
	operationID string
	file        string
	template    string
	outcome     appstorecrypto.DeliveryOutcome
}

func (f *textHydratorFake) Hydrate(_ context.Context, operationID, file string, template []byte) appstorecrypto.DeliveryOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls++
	f.operationID = operationID
	f.file = file
	f.template = string(template)
	return f.outcome
}

func (f *textHydratorFake) snapshot() (int, string, string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.operationID, f.file, f.template
}

func postRPC(t *testing.T, client *http.Client, bootstrap Bootstrap, method string, arguments any, change func(*http.Request)) (int, []byte) {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      method,
			"arguments": arguments,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodPost, bootstrap.Endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if change != nil {
		change(request)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

func TestTextAdapterCapabilityIsOptIn(t *testing.T) {
	tests := []struct {
		name       string
		adapter    TextHydrator
		advertised bool
	}{
		{name: "disabled", adapter: nil, advertised: false},
		{name: "enabled", adapter: &textHydratorFake{}, advertised: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runnerCalls := 0
			var server *Server
			var err error
			runner := func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
				runnerCalls++
				return 0, nil
			}
			if tc.adapter == nil {
				server, err = Listen(context.Background(), "selected", runner)
			} else {
				server, err = ListenWithTextAdapter(context.Background(), "selected", runner, tc.adapter)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			bootstrap := server.Bootstrap()
			client := transportClient(t, bootstrap)
			code, data := postInfo(t, client, bootstrap, nil)
			if code != http.StatusOK {
				t.Fatalf("info status %d: %s", code, data)
			}

			var reply struct {
				Result struct {
					StructuredContent InfoOutput `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal(data, &reply); err != nil {
				t.Fatal(err)
			}

			found := false
			for _, capability := range reply.Result.StructuredContent.Capabilities {
				if capability == "text_hydrate" {
					found = true
				}
			}
			if found != tc.advertised {
				t.Fatalf("text_hydrate advertised=%v, want %v", found, tc.advertised)
			}

			if tc.adapter == nil {
				status, body := postRPC(t, client, bootstrap, "text_hydrate", map[string]any{
					"operation_id": "op",
					"file":         "file",
					"mode":         "hydrate-v1",
					"template":     "template",
				}, nil)
				if status != http.StatusOK {
					t.Fatalf("disabled adapter call status %d: %s", status, body)
				}

				var failure struct {
					Error *struct {
						Code    int    `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if err := json.Unmarshal(body, &failure); err != nil {
					t.Fatalf("decode disabled adapter response: %v", err)
				}
				if failure.Error == nil || failure.Error.Message == "" {
					t.Fatalf("disabled adapter call did not return a tool failure: %s", body)
				}
			}

			if runnerCalls != 0 {
				t.Fatal("generic stream runner invoked during info/text-hydrate RPC")
			}
		})
	}
}

func TestTextHydrateHandlerContract(t *testing.T) {
	fake := &textHydratorFake{
		outcome: appstorecrypto.DeliveryOutcome{Status: appstorecrypto.DeliveryReceived},
	}
	runnerCalls := 0
	server, err := ListenWithTextAdapter(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		runnerCalls++
		return 0, nil
	}, fake)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	bootstrap := server.Bootstrap()
	client := transportClient(t, bootstrap)
	const op, file, template = "operation-123", "secrets.txt", "prefix {{secret}} suffix"
	code, data := postRPC(t, client, bootstrap, "text_hydrate", map[string]any{
		"operation_id": op,
		"file":         file,
		"mode":         "hydrate-v1",
		"template":     template,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("hydrate status %d: %s", code, data)
	}

	calls, gotOp, gotFile, gotTemplate := fake.snapshot()
	if calls != 1 || gotOp != op || gotFile != file || gotTemplate != template {
		t.Fatalf("callback contract: calls=%d op=%q file=%q template=%q", calls, gotOp, gotFile, gotTemplate)
	}
	if bytes.Contains(data, []byte("prefix")) || bytes.Contains(data, []byte("{{secret}}")) || bytes.Contains(data, []byte("suffix")) {
		t.Fatalf("template content leaked in reply: %s", data)
	}

	var reply struct {
		Result struct {
			StructuredContent TextHydrateOutput `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &reply); err != nil || reply.Result.StructuredContent.Status != "received" {
		t.Fatalf("status-only result missing: %s (err %v)", data, err)
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(reply.Result.StructuredContent)
	if strings.Contains(string(encoded), "template") {
		t.Fatalf("output includes template data: %s", encoded)
	}
	if runnerCalls != 0 {
		t.Fatal("text hydration invoked generic stream runner")
	}
}

func TestTextHydrateStatusMappingValidationAndAuthentication(t *testing.T) {
	tests := []struct {
		name    string
		outcome appstorecrypto.DeliveryOutcome
		want    string
	}{
		{name: "withheld", outcome: appstorecrypto.DeliveryOutcome{Status: appstorecrypto.DeliveryWithheld}, want: "withheld"},
		{name: "unknown", outcome: appstorecrypto.DeliveryOutcome{}, want: "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &textHydratorFake{outcome: tc.outcome}
			server, err := ListenWithTextAdapter(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
				return 0, nil
			}, fake)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			bootstrap := server.Bootstrap()
			client := transportClient(t, bootstrap)
			code, data := postRPC(t, client, bootstrap, "text_hydrate", map[string]any{
				"operation_id": "op",
				"file":         "f",
				"mode":         "hydrate-v1",
				"template":     "t",
			}, nil)
			if code != http.StatusOK || !bytes.Contains(data, []byte(`"status":"`+tc.want+`"`)) {
				t.Fatalf("mapping status=%d body=%s", code, data)
			}
		})
	}

	fake := &textHydratorFake{
		outcome: appstorecrypto.DeliveryOutcome{Status: appstorecrypto.DeliveryReceived},
	}
	server, err := ListenWithTextAdapter(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		return 0, nil
	}, fake)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	bootstrap := server.Bootstrap()
	client := transportClient(t, bootstrap)
	invalidArguments := []map[string]any{
		{
			"operation_id": "op",
			"file":         "f",
			"mode":         "reverse-v1",
			"template":     "t",
		},
		{
			"operation_id": "op",
			"file":         "f",
			"mode":         "hydrate-v1",
			"template":     strings.Repeat("x", 32<<10+1),
		},
	}
	for _, arguments := range invalidArguments {
		code, _ := postRPC(t, client, bootstrap, "text_hydrate", arguments, nil)
		if code != http.StatusOK {
			t.Fatalf("invalid RPC HTTP status %d", code)
		}
	}
	if calls, _, _, _ := fake.snapshot(); calls != 0 {
		t.Fatalf("invalid requests reached callback %d times", calls)
	}

	code, _ := postRPC(t, client, bootstrap, "text_hydrate", map[string]any{
		"operation_id": "op",
		"file":         "f",
		"mode":         "hydrate-v1",
		"template":     "t",
	}, func(request *http.Request) {
		request.Header.Del("Authorization")
	})
	if code != http.StatusForbidden {
		t.Fatalf("unauthenticated status=%d, want forbidden", code)
	}
	if calls, _, _, _ := fake.snapshot(); calls != 0 {
		t.Fatalf("unauthenticated request reached callback %d times", calls)
	}
}

func TestTextAdapterOmitsGenericTransportTools(t *testing.T) {
	fake := &textHydratorFake{
		outcome: appstorecrypto.DeliveryOutcome{Status: appstorecrypto.DeliveryWithheld},
	}
	runnerCalls := 0
	server, err := ListenWithTextAdapter(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		runnerCalls++
		return 0, nil
	}, fake)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	bootstrap := server.Bootstrap()
	client := transportClient(t, bootstrap)
	for _, name := range []string{"transport_start", "transport_input", "transport_read", "transport_cancel"} {
		status, body := postRPC(t, client, bootstrap, name, map[string]any{}, nil)
		if status != http.StatusOK {
			t.Fatalf("%s status %d: %s", name, status, body)
		}

		var response struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("decode %s response: %v", name, err)
		}
		if response.Error == nil {
			t.Fatalf("%s unexpectedly succeeded: %s", name, body)
		}
	}
	if runnerCalls != 0 {
		t.Fatalf("generic stream runner called %d times", runnerCalls)
	}
	if calls, _, _, _ := fake.snapshot(); calls != 0 {
		t.Fatalf("text adapter called %d times", calls)
	}

	status, body := postInfo(t, client, bootstrap, nil)
	if status != http.StatusOK {
		t.Fatalf("info status %d: %s", status, body)
	}
	var info struct {
		Result struct {
			StructuredContent InfoOutput `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatalf("decode info response: %v", err)
	}
	want := []string{"text_hydrate"}
	capabilities := info.Result.StructuredContent.Capabilities
	if len(capabilities) != len(want) || capabilities[0] != want[0] {
		t.Fatalf("capabilities = %v, want exactly %v", capabilities, want)
	}
}
