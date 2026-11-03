//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func connectedReverseStreamChild(t *testing.T) {
	grantPipe, ack := os.NewFile(3, "grant"), os.NewFile(4, "ack")
	if grantPipe == nil || ack == nil {
		t.Fatal("missing reverse stream authority pipes")
	}
	defer grantPipe.Close()
	defer ack.Close()
	installation, grant, placeholder := appstorecrypto.TextAdapterFixture(t)
	target, runner, credential := newPairTargetWithLimit(t, grant.Profile, 64<<20)
	grant.Mode, grant.RecipientUID, grant.CredentialSHA256, grant.Command, grant.File = "reverse-copy-stream-v2", os.Geteuid(), credential, "pair-read", target.path
	if err := json.NewEncoder(grantPipe).Encode(grant); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ack, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	prefix := bytes.Repeat([]byte("large synthetic reverse config\n"), 50000)
	for _, test := range []struct {
		name    string
		tail    []byte
		success bool
	}{
		{"large-exact-copy", []byte(connectedSecret), true},
		{"late-invalid-utf8", []byte{0xff}, false},
		{"late-nul", []byte{0}, false},
		{"late-raw-placeholder", []byte(placeholder), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := append(append([]byte(nil), prefix...), test.tail...)
			defer clear(input)
			if err := os.WriteFile(target.path, input, 0o600); err != nil {
				t.Fatal(err)
			}
			adapter, err := appstorecrypto.NewReverseTextStreamAdapter(ctx, installation, grant.ID, grant.Profile, credential, runner)
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			server, err := apptransport.ListenWithReverseTextStreamAdapter(ctx, grant.Profile, runner, adapter)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			bootstrap := server.Bootstrap()
			tlsConfig, err := wire.ClientTLS(bootstrap.Pin)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			defer client.CloseIdleConnections()
			operation := "AAECAwQFBgcICQoLDA0ODw"
			header := apptransport.TextStreamHeader{Format: apptransport.TextStreamFormat, OperationID: operation, Profile: grant.Profile, File: grant.File, References: grant.References}
			post := func(path string, metadata apptransport.TextStreamHeader) *http.Response {
				var body bytes.Buffer
				if err := json.NewEncoder(&body).Encode(metadata); err != nil {
					t.Fatal(err)
				}
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(bootstrap.Endpoint, "/mcp")+path, &body)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
				request.Header.Set("Content-Type", "application/x-ndjson")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				return response
			}
			accepted := target.accepted.Load()
			wrong := header
			wrong.References = []string{"wrong-ref"}
			refused := post(apptransport.TextStreamReversePath, wrong)
			refused.Body.Close()
			if refused.StatusCode != http.StatusForbidden || target.accepted.Load() != accepted {
				t.Fatal("reverse scope refusal contacted SSH")
			}
			forward := post(apptransport.TextStreamPreparePath, header)
			forward.Body.Close()
			if forward.StatusCode != http.StatusForbidden || target.accepted.Load() != accepted {
				t.Fatal("reverse grant enabled forward delivery")
			}
			reads := target.reads.Load()
			response := post(apptransport.TextStreamReversePath, header)
			defer response.Body.Close()
			var output bytes.Buffer
			err = appstoretextstream.Decode(ctx, response.Body, &output, operation, appstoretextstream.MaxBytes)
			if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/x-ndjson" || target.reads.Load() != reads+1 {
				t.Fatal("reverse request did not use actual authenticated SSH")
			}
			if test.success {
				want := append(append([]byte(nil), prefix...), []byte(placeholder)...)
				if err != nil || len(output.Bytes()) <= 1<<20 || !bytes.Equal(output.Bytes(), want) {
					t.Fatal("large reverse copy did not match the exact reference-only source")
				}
			} else if err == nil {
				t.Fatal("late reverse failure emitted successful completion")
			}
			if bytes.Contains(output.Bytes(), []byte(connectedSecret)) || bytes.Contains(output.Bytes(), []byte(pairLongSecret)) {
				t.Fatal("reverse response exposed selected values or SSH stderr")
			}
			stored, err := os.ReadFile(target.path)
			if err != nil || !bytes.Equal(stored, input) {
				t.Fatal("reverse streaming changed the live source")
			}
			clear(stored)
			accepted = target.accepted.Load()
			replay := post(apptransport.TextStreamReversePath, header)
			defer replay.Body.Close()
			var reply apptransport.TextStreamReply
			if json.NewDecoder(replay.Body).Decode(&reply) != nil || reply.Status != "withheld" || target.accepted.Load() != accepted {
				t.Fatal("reverse single-use operation was replayed")
			}
		})
	}
}
