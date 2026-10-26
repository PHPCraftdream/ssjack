package apptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

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
		"SSJACK_APP_ENDPOINT=old", "ssjack_app_certificate_sha256=old", "UNRELATED=value",
	}
	out := Environment(base, bootstrap)
	if len(out) != 5 || !strings.Contains(strings.Join(out, "\n"), EnvToken+"=child-token") {
		t.Fatalf("unexpected environment: %v", out)
	}
	if strings.Contains(strings.Join(out, "\n"), "main-secret") || strings.Contains(strings.Join(out, "\n"), "old") {
		t.Fatal("inherited capability was forwarded")
	}
	if !strings.Contains(strings.Join(base, "\n"), "main-secret") {
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
