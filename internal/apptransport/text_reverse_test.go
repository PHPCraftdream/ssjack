package apptransport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
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
