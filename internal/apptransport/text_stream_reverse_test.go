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

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
)

type reverseStreamFake struct {
	data   []byte
	status appstorecrypto.DeliveryStatus
	calls  atomic.Int32
}

func (*reverseStreamFake) MatchReverseScope(profile, file string, refs []string) error {
	if profile != "selected" || file != "/approved/config" || len(refs) != 1 || refs[0] != "selected-ref" {
		return appstorecrypto.ErrDelivery
	}
	return nil
}

func (f *reverseStreamFake) ReverseCopyStream(_ context.Context, _, _ string, output io.WriteCloser) appstorecrypto.DeliveryOutcome {
	f.calls.Add(1)
	if _, err := io.Copy(output, bytes.NewReader(f.data)); err != nil {
		output.Close()
		return appstorecrypto.DeliveryOutcome{Status: appstorecrypto.DeliveryUnknown}
	}
	output.Close()
	return appstorecrypto.DeliveryOutcome{Status: f.status}
}

func reverseStreamRequest(t *testing.T) []byte {
	t.Helper()
	body := streamBody(t, false, nil)
	return body[:bytes.IndexByte(body, '\n')+1]
}

func TestReverseStreamHTTPRequiresFinalReceivedOutcome(t *testing.T) {
	for _, test := range []struct {
		name   string
		data   []byte
		status appstorecrypto.DeliveryStatus
	}{
		{"large-received", bytes.Repeat([]byte("reference-only config\n"), 100000), appstorecrypto.DeliveryReceived},
		{"large-unknown", bytes.Repeat([]byte("tentative config\n"), 100000), appstorecrypto.DeliveryUnknown},
		{"empty-received", nil, appstorecrypto.DeliveryReceived},
		{"empty-withheld", nil, appstorecrypto.DeliveryWithheld},
		{"empty-unknown", nil, appstorecrypto.DeliveryUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter := &reverseStreamFake{data: test.data, status: test.status}
			server, err := ListenWithReverseTextStreamAdapter(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 1, nil }, adapter)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			bootstrap := server.Bootstrap()
			client := transportClient(t, bootstrap)
			request, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(bootstrap.Endpoint, "/mcp")+TextStreamReversePath, bytes.NewReader(reverseStreamRequest(t)))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
			request.Header.Set("Content-Type", "application/x-ndjson")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatal("reverse HTTP failed")
			}
			if len(test.data) == 0 && test.status != appstorecrypto.DeliveryReceived {
				var reply TextStreamReply
				expected := "unknown"
				if test.status == appstorecrypto.DeliveryWithheld {
					expected = "withheld"
				}
				if json.NewDecoder(response.Body).Decode(&reply) != nil || reply.Status != expected || response.Header.Get("Content-Type") != "application/json" {
					t.Fatal("empty refusal did not return bounded status metadata")
				}
			} else {
				var decoded bytes.Buffer
				err := appstoretextstream.Decode(context.Background(), response.Body, &decoded, "AAECAwQFBgcICQoLDA0ODw", appstoretextstream.MaxBytes)
				if test.status == appstorecrypto.DeliveryReceived {
					if err != nil || !bytes.Equal(decoded.Bytes(), test.data) {
						t.Fatal("large reverse response was incomplete or changed")
					}
				} else if err == nil {
					t.Fatal("unknown producer emitted a successful terminal frame")
				}
			}
			if adapter.calls.Load() != 1 {
				t.Fatal("reverse producer dispatch count changed")
			}
		})
	}
}

func TestReverseStreamHTTPRefusesOtherScopesAndRoutes(t *testing.T) {
	adapter := &reverseStreamFake{status: appstorecrypto.DeliveryReceived}
	server, err := ListenWithReverseTextStreamAdapter(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		t.Error("raw runner invoked")
		return 1, nil
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	bootstrap := server.Bootstrap()
	client := transportClient(t, bootstrap)
	body := reverseStreamRequest(t)
	for _, test := range []struct {
		path  string
		body  []byte
		token string
		code  int
	}{
		{TextStreamReversePath, body, "wrong", http.StatusForbidden},
		{TextStreamPreparePath, body, bootstrap.Token, http.StatusForbidden},
		{TextStreamExecutePath, body, bootstrap.Token, http.StatusForbidden},
		{TextStreamReversePath, bytes.Replace(body, []byte("selected-ref"), []byte("wrong-ref"), 1), bootstrap.Token, http.StatusForbidden},
		{TextStreamReversePath, append(append([]byte(nil), body...), 'x'), bootstrap.Token, http.StatusBadRequest},
	} {
		code, _ := postTextStream(t, client, bootstrap, test.path, test.body, test.token)
		if code != test.code {
			t.Fatal("reverse request escaped its closed scope")
		}
	}
	if adapter.calls.Load() != 0 {
		t.Fatal("refused request invoked reverse producer")
	}
	_, encoded := postRPC(t, client, bootstrap, "transport_start", map[string]string{"command": "forbidden"}, nil)
	if !bytes.Contains(encoded, []byte("error")) && !bytes.Contains(encoded, []byte("isError")) {
		t.Fatal("reverse listener exposed raw execution")
	}
	_, encoded = postInfo(t, client, bootstrap, nil)
	var info struct {
		Result struct {
			StructuredContent InfoOutput `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(encoded, &info) != nil || info.Result.StructuredContent.Protocol != 2 || len(info.Result.StructuredContent.Capabilities) != 1 || info.Result.StructuredContent.Capabilities[0] != "text_reverse_copy_stream_v2" {
		t.Fatal("reverse listener advertised other capabilities")
	}
	legacy, err := Listen(context.Background(), "selected", func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 1, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	b := legacy.Bootstrap()
	if code, _ := postTextStream(t, transportClient(t, b), b, TextStreamReversePath, body, b.Token); code != http.StatusForbidden {
		t.Fatal("legacy listener enabled reverse streaming")
	}
}
