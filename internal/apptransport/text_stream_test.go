package apptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
)

type streamHydratorFake struct {
	mu       sync.Mutex
	prepared int
	executed int
	bytes    int64
}

func (f *streamHydratorFake) MatchScope(profile, file string, refs []string) error {
	if profile != "selected" || file != "/approved/config" || len(refs) != 1 || refs[0] != "selected-ref" {
		return appstorecrypto.ErrDelivery
	}
	return nil
}
func (f *streamHydratorFake) Prepare(_ context.Context, _, _ string, input io.Reader) (appstorecrypto.TextStreamPreparation, error) {
	f.mu.Lock()
	f.prepared++
	f.mu.Unlock()
	count, err := io.Copy(io.Discard, input)
	f.mu.Lock()
	f.bytes = count
	f.mu.Unlock()
	if err != nil {
		return appstorecrypto.TextStreamPreparation{}, err
	}
	return appstorecrypto.TextStreamPreparation{Ticket: "AAECAwQFBgcICQoLDA0ODw", Bytes: uint64(count)}, nil
}
func (f *streamHydratorFake) Execute(_ context.Context, _, _, _ string, input io.ReadCloser) appstorecrypto.DeliveryOutcome {
	defer input.Close()
	f.mu.Lock()
	f.executed++
	f.mu.Unlock()
	if _, err := io.Copy(io.Discard, input); err != nil {
		return appstorecrypto.DeliveryOutcome{Status: appstorecrypto.DeliveryUnknown}
	}
	return appstorecrypto.DeliveryOutcome{Status: appstorecrypto.DeliveryReceived}
}

func streamBody(t *testing.T, execute bool, input []byte) []byte {
	t.Helper()
	header := TextStreamHeader{Format: TextStreamFormat, OperationID: "AAECAwQFBgcICQoLDA0ODw", Profile: "selected", File: "/approved/config", References: []string{"selected-ref"}}
	if execute {
		header.Ticket = "AAECAwQFBgcICQoLDA0ODw"
	}
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(header); err != nil {
		t.Fatal(err)
	}
	if err := appstoretextstream.Encode(context.Background(), bytes.NewReader(input), &body, header.OperationID, appstoretextstream.MaxBytes); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func postTextStream(t *testing.T, client *http.Client, bootstrap Bootstrap, path string, body []byte, token string) (int, []byte) {
	t.Helper()
	endpoint := strings.TrimSuffix(bootstrap.Endpoint, "/mcp") + path
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/x-ndjson")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, encoded
}

func TestPrivateStreamRouteRequiresOptInAndToken(t *testing.T) {
	adapter := &streamHydratorFake{}
	runner := func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		return 0, appstorecrypto.ErrDelivery
	}
	server, err := ListenWithTextStreamAdapter(context.Background(), "selected", runner, adapter)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	bootstrap := server.Bootstrap()
	client := transportClient(t, bootstrap)
	body := streamBody(t, false, []byte("template"))
	if code, _ := postTextStream(t, client, bootstrap, TextStreamPreparePath, body, "wrong"); code != http.StatusForbidden {
		t.Fatal("private stream accepted another bearer")
	}
	for _, changed := range [][]byte{
		bytes.Replace(body, []byte(`"profile":"selected"`), []byte(`"profile":"other"`), 1),
		bytes.Replace(body, []byte(`/approved/config`), []byte(`/wrong/config`), 1),
		bytes.Replace(body, []byte(`selected-ref`), []byte(`another-ref`), 1),
		bytes.Replace(body, []byte(TextStreamFormat), []byte("ssjack-text-stream-v1"), 1),
	} {
		if bytes.Equal(changed, body) {
			t.Fatal("scope refusal fixture did not change the header")
		}
		if code, _ := postTextStream(t, client, bootstrap, TextStreamPreparePath, changed, bootstrap.Token); code != http.StatusForbidden {
			t.Fatal("private stream accepted another profile/file/reference scope")
		}
	}
	legacy, err := Listen(context.Background(), "selected", runner)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if code, _ := postTextStream(t, transportClient(t, legacy.Bootstrap()), legacy.Bootstrap(), TextStreamPreparePath, body, legacy.Bootstrap().Token); code != http.StatusForbidden {
		t.Fatal("legacy transport silently enabled streaming")
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.prepared != 0 || adapter.executed != 0 {
		t.Fatal("refused transport request reached the producer")
	}
}

func TestPrivateStreamRouteTransfersLargeFramesAndRejectsMissingCompletion(t *testing.T) {
	adapter := &streamHydratorFake{}
	server, err := ListenWithTextStreamAdapter(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 1, nil }, adapter)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	bootstrap := server.Bootstrap()
	client := transportClient(t, bootstrap)
	input := bytes.Repeat([]byte("synthetic stream\n"), 140000)
	body := streamBody(t, false, input)
	code, encoded := postTextStream(t, client, bootstrap, TextStreamPreparePath, body, bootstrap.Token)
	var reply TextStreamReply
	if code != http.StatusOK || json.Unmarshal(encoded, &reply) != nil || reply.Status != "prepared" || reply.Bytes != uint64(len(input)) || reply.Ticket == "" {
		t.Fatal("private preparation did not require a complete large frame stream")
	}
	body = streamBody(t, true, input)
	code, encoded = postTextStream(t, client, bootstrap, TextStreamExecutePath, body, bootstrap.Token)
	if code != http.StatusOK || json.Unmarshal(encoded, &reply) != nil || reply.Status != "received" {
		t.Fatal("complete private execution stream failed")
	}
	truncated := body[:bytes.LastIndexByte(body[:len(body)-1], '\n')+1]
	code, encoded = postTextStream(t, client, bootstrap, TextStreamExecutePath, truncated, bootstrap.Token)
	if code != http.StatusOK || json.Unmarshal(encoded, &reply) != nil || reply.Status != "unknown" {
		t.Fatal("lost stream completion was accepted as received")
	}
}

func TestPrivateStreamProfileDoesNotExposeRawExecutionTools(t *testing.T) {
	var rawCalls atomic.Int32
	server, err := ListenWithTextStreamAdapter(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		rawCalls.Add(1)
		return 1, nil
	}, &streamHydratorFake{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client := transportClient(t, server.Bootstrap())
	code, encoded := postInfo(t, client, server.Bootstrap(), nil)
	var response struct {
		Result struct {
			StructuredContent InfoOutput `json:"structuredContent"`
		} `json:"result"`
	}
	if code != http.StatusOK || json.Unmarshal(encoded, &response) != nil || response.Result.StructuredContent.Protocol != 2 || len(response.Result.StructuredContent.Capabilities) != 1 || response.Result.StructuredContent.Capabilities[0] != "text_hydrate_stream_v2" {
		t.Fatal("private stream advertised a legacy/raw capability")
	}
	_, encoded = postRPC(t, client, server.Bootstrap(), "transport_start", map[string]string{"command": "forbidden"}, nil)
	if rawCalls.Load() != 0 || (!bytes.Contains(encoded, []byte("error")) && !bytes.Contains(encoded, []byte("isError"))) {
		t.Fatal("private stream exposed the raw execution tool")
	}
}
