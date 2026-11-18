package apptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func transportClient(t *testing.T, bootstrap Bootstrap) *http.Client {
	t.Helper()
	config, err := wire.ClientTLS(bootstrap.Pin)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: config}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func postInfo(t *testing.T, client *http.Client, bootstrap Bootstrap, change func(*http.Request)) (int, []byte) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transport_info","arguments":{}}}`
	request, err := http.NewRequest(http.MethodPost, bootstrap.Endpoint, strings.NewReader(body))
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

func TestScopedServerAuthenticationAndProtocol(t *testing.T) {
	s, err := Listen(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bootstrap := s.Bootstrap()
	if !strings.HasPrefix(bootstrap.Endpoint, "https://127.0.0.1:") || len(bootstrap.Token) != 64 || len(bootstrap.Pin) != 64 {
		t.Fatal("invalid scoped bootstrap")
	}
	client := transportClient(t, bootstrap)
	code, data := postInfo(t, client, bootstrap, nil)
	if code != http.StatusOK {
		t.Fatalf("info failed: %d %s", code, data)
	}
	var reply struct {
		Result struct {
			StructuredContent InfoOutput `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &reply) != nil || reply.Result.StructuredContent.Protocol != Protocol || reply.Result.StructuredContent.Profile != "selected" {
		t.Fatalf("missing protocol or scope: %s", data)
	}
	if bytes.Contains(data, []byte(bootstrap.Token)) || bytes.Contains(data, []byte(bootstrap.Pin)) {
		t.Fatal("bootstrap secret escaped through info")
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") },
		func(r *http.Request) { r.Header.Del("Authorization") },
		func(r *http.Request) { r.Header.Set("Origin", "https://example.invalid") },
		func(r *http.Request) { r.Host = "localhost" },
		func(r *http.Request) { r.URL.Path = "/other" },
		func(r *http.Request) { r.URL.RawQuery = "token=ignored" },
	} {
		if code, _ := postInfo(t, client, bootstrap, change); code != http.StatusForbidden {
			t.Fatalf("invalid request was not denied: %d", code)
		}
	}
	if code, _ := postInfo(t, client, bootstrap, func(r *http.Request) { r.Method = http.MethodGet }); code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected method accepted: %d", code)
	}
}

func TestScopedServerRevocationAndIsolation(t *testing.T) {
	stopped := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := Listen(ctx, "selected", func(ctx context.Context, target, _ string, _ io.Reader, _, _ io.Writer) (int, error) {
		defer close(stopped)
		if target != "selected" {
			t.Error("delegated profile changed")
		}
		<-ctx.Done()
		return -1, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	other, err := Listen(ctx, "other", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	job, err := s.streams.start(StartInput{Command: "wait"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.streams.stop(JobInput{JobID: job.JobID}); err == nil {
		t.Fatal("another scoped server could cancel the operation")
	}
	cancel()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("parent cancellation did not close the child transport")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("parent cancellation did not stop the SSH runner")
	}
	client := transportClient(t, s.Bootstrap())
	if _, err := client.Get(s.Bootstrap().Endpoint); err == nil {
		t.Fatal("revoked transport remained reachable")
	}
}

func TestScopedEnvironmentDoesNotForwardMainBootstrap(t *testing.T) {
	bootstrap := Bootstrap{Endpoint: "endpoint", Token: "child-token", Pin: "pin"}
	base := []string{
		"PATH=original", "SSJACK_ENV_TOKEN=main-secret", "ssjack_session=old", "SSJACK_ENDPOINT=old",
		"SSJACK_CERTIFICATE_SHA256=old", "SSJACK_BOOTSTRAP_FILE=old", "SSJACK_APP_TOKEN=old-child",
		"SSJACK_APP_ENDPOINT=old", "ssjack_app_certificate_sha256=old", "SSJACK_REMOTE_MCP_CHANNELS=stale",
		"ssjack_remote_mcp_channels=inherited", "UNRELATED=value",
	}
	parent := append([]string(nil), base...)
	out := Environment(base, bootstrap)
	joined := strings.Join(out, "\n")
	if len(out) != 5 || !strings.Contains(joined, EnvEndpoint+"=endpoint") ||
		!strings.Contains(joined, EnvToken+"=child-token") || !strings.Contains(joined, EnvPin+"=pin") {
		t.Fatalf("unexpected environment: %v", out)
	}
	if strings.Contains(joined, "main-secret") || strings.Contains(joined, "old") ||
		strings.Contains(joined, "stale") || strings.Contains(joined, "inherited") {
		t.Fatal("inherited capability was forwarded")
	}
	if strings.Join(base, "\n") != strings.Join(parent, "\n") {
		t.Fatal("parent environment was mutated")
	}
}

func TestScopedServerRejectsInvalidScope(t *testing.T) {
	if _, err := Listen(context.Background(), "", nil); err == nil {
		t.Fatal("invalid child scope accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Listen(ctx, "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil }); err == nil {
		t.Fatal("cancelled scope accepted")
	}
}

// registerStallDiag adds failure-only goroutine dump evidence for tests whose
// channel waits can stall under CI timing pressure.
func registerStallDiag(t *testing.T) {
	t.Helper()
	flakediag.OnFailure(t, func() string {
		return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
}

func sendInput(ctx context.Context, s *streams, id string, data []byte) error {
	for len(data) > 0 {
		n := min(len(data), ChunkSize)
		out, err := s.write(InputInput{JobID: id, Data: base64.StdEncoding.EncodeToString(data[:n])})
		if err != nil {
			return err
		}
		if out.Accepted {
			data = data[n:]
		} else {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
	}
	for {
		out, err := s.write(InputInput{JobID: id, EOF: true})
		if err != nil {
			return err
		}
		if out.Accepted {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func TestStreamsBinaryRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte{0, 255, 128, '\n', 0xC3, 0xA9}, 180000)
	stderr := []byte{0xFF, 0, 42}
	s := newStreams(ctx, "selected", func(ctx context.Context, target, command string, stdin io.Reader, stdout, errorOut io.Writer) (int, error) {
		if target != "selected" || command != "copy" {
			return -1, errors.New("unexpected scope")
		}
		if _, err := io.Copy(stdout, stdin); err != nil {
			return -1, err
		}
		_, err := errorOut.Write(stderr)
		return 23, err
	})
	defer s.close()
	started, err := s.start(StartInput{Command: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() { sent <- sendInput(ctx, s, started.JobID, payload) }()
	var output, errorOutput bytes.Buffer
	for {
		out, err := s.read(ctx, JobInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if out.Done {
			if out.ExitCode != 23 || out.Error != "" || out.TimedOut {
				t.Fatalf("unexpected result: %+v", out)
			}
			break
		}
		if out.Pending {
			continue
		}
		data, err := base64.StdEncoding.Strict().DecodeString(out.Data)
		if err != nil || len(data) > ChunkSize {
			t.Fatal("invalid binary frame")
		}
		switch out.Stream {
		case "stdout":
			output.Write(data)
		case "stderr":
			errorOutput.Write(data)
		default:
			t.Fatal("unknown output stream")
		}
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), payload) || !bytes.Equal(errorOutput.Bytes(), stderr) {
		t.Fatal("transport corrupted binary data")
	}
}

func TestStreamsBackpressureCancellation(t *testing.T) {
	registerStallDiag(t)
	full := make(chan struct{})
	finished := make(chan struct{})
	s := newStreams(context.Background(), "selected", func(ctx context.Context, _, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		defer close(finished)
		chunk := make([]byte, ChunkSize)
		for range 16 {
			if _, err := stdout.Write(chunk); err != nil {
				return -1, err
			}
		}
		close(full)
		_, err := stdout.Write(chunk)
		return -1, err
	})
	defer s.close()
	started, err := s.start(StartInput{Command: "produce"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-full:
	case <-time.After(5 * time.Second):
		t.Fatal("producer did not fill its bounded queue")
	}
	select {
	case <-finished:
		t.Fatal("producer bypassed output backpressure")
	default:
	}
	if _, err := s.stop(JobInput{JobID: started.JobID}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not release a blocked producer")
	}
}

func TestStreamsDeadlineAndValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := newStreams(ctx, "selected", func(_ context.Context, _, _ string, stdin io.Reader, _, _ io.Writer) (int, error) {
		_, err := io.Copy(io.Discard, stdin)
		return -1, err
	})
	defer s.close()
	for _, input := range []StartInput{{}, {Command: "a\x00b"}, {Command: "x", TimeoutMS: -1}, {Command: "x", TimeoutMS: 3600001}} {
		if _, err := s.start(input); err == nil {
			t.Fatalf("accepted invalid start: %+v", input)
		}
	}
	started, err := s.start(StartInput{Command: "wait", TimeoutMS: 25})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []InputInput{
		{JobID: started.JobID, Data: "not base64"},
		{JobID: started.JobID, Data: "YQ==", EOF: true},
		{JobID: "unknown", Data: "YQ=="},
	} {
		if _, err := s.write(input); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
	for {
		out, err := s.read(ctx, JobInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if out.Done {
			if !out.TimedOut || out.Error != context.DeadlineExceeded.Error() {
				t.Fatalf("missing deadline evidence: %+v", out)
			}
			break
		}
	}
}

func TestStreamsInputEOFAndConcurrency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := newStreams(ctx, "selected", func(ctx context.Context, _, _ string, _ io.Reader, _, _ io.Writer) (int, error) {
		<-ctx.Done()
		return -1, ctx.Err()
	})
	defer s.close()
	var id string
	for range maxActive {
		out, err := s.start(StartInput{Command: "wait"})
		if err != nil {
			t.Fatal(err)
		}
		id = out.JobID
	}
	if _, err := s.start(StartInput{Command: "excess"}); err == nil {
		t.Fatal("concurrency limit was bypassed")
	}
	if out, err := s.write(InputInput{JobID: id, EOF: true}); err != nil || !out.Accepted {
		t.Fatal("EOF was not accepted")
	}
	if out, err := s.write(InputInput{JobID: id, EOF: true}); err != nil || !out.Accepted {
		t.Fatal("repeated EOF was not idempotent")
	}
	if _, err := s.write(InputInput{JobID: id, Data: "YQ=="}); err == nil {
		t.Fatal("input was accepted after EOF")
	}
}

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
