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

func connectedStreamChild(t *testing.T) {
	grantPipe, ack := os.NewFile(3, "grant"), os.NewFile(4, "ack")
	if grantPipe == nil || ack == nil {
		t.Fatal("missing stream authority pipes")
	}
	defer grantPipe.Close()
	defer ack.Close()
	installation, grant, placeholder := appstorecrypto.TextAdapterFixture(t)
	target, runner, credential := newPairTargetWithLimit(t, grant.Profile, 64<<20)
	grant.Mode, grant.RecipientUID, grant.CredentialSHA256, grant.Command, grant.File = "hydrate-stream-v2", os.Geteuid(), credential, "pair-write", target.path
	if err := json.NewEncoder(grantPipe).Encode(grant); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ack, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	adapter, err := appstorecrypto.NewTextStreamAdapter(ctx, installation, grant.ID, grant.Profile, credential, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	server, err := apptransport.ListenWithTextStreamAdapter(ctx, grant.Profile, runner, adapter)
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
	header := apptransport.TextStreamHeader{Format: apptransport.TextStreamFormat, OperationID: operation, Profile: grant.Profile, File: grant.File, References: append([]string(nil), grant.References...)}
	encode := func(metadata apptransport.TextStreamHeader, input []byte) []byte {
		var body bytes.Buffer
		if err := json.NewEncoder(&body).Encode(metadata); err != nil {
			t.Fatal(err)
		}
		if err := appstoretextstream.Encode(ctx, bytes.NewReader(input), &body, operation, appstoretextstream.MaxBytes); err != nil {
			t.Fatal(err)
		}
		return body.Bytes()
	}
	post := func(path string, body []byte) (int, apptransport.TextStreamReply) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(bootstrap.Endpoint, "/mcp")+path, bytes.NewReader(body))
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
		body, err = io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil || bytes.Contains(body, []byte(connectedSecret)) || bytes.Contains(body, []byte(pairLongSecret)) {
			t.Fatal("private stream response leaked consumer data or failed")
		}
		var reply apptransport.TextStreamReply
		if response.StatusCode == http.StatusOK && json.Unmarshal(body, &reply) != nil {
			t.Fatal("private stream response was malformed")
		}
		return response.StatusCode, reply
	}
	wrong := header
	wrong.References = []string{"not-selected"}
	if status, _ := post(apptransport.TextStreamPreparePath, encode(wrong, []byte("template"))); status != http.StatusForbidden || target.accepted.Load() != 0 {
		t.Fatal("wrong-reference preparation contacted SSH")
	}
	if status, reply := post(apptransport.TextStreamPreparePath, encode(header, []byte("invalid $ssjack marker"))); status != http.StatusOK || reply.Status != "withheld" || target.accepted.Load() != 0 {
		t.Fatal("malformed preparation was not withheld before SSH")
	}
	missing := encode(header, []byte("template"))
	missing = missing[:bytes.LastIndexByte(missing[:len(missing)-1], '\n')+1]
	if status, reply := post(apptransport.TextStreamPreparePath, missing); status != http.StatusOK || reply.Status != "withheld" || target.accepted.Load() != 0 {
		t.Fatal("incomplete preparation contacted SSH")
	}
	input := append(bytes.Repeat([]byte("large synthetic config\n"), 70000), []byte(placeholder)...)
	status, prepared := post(apptransport.TextStreamPreparePath, encode(header, input))
	if status != http.StatusOK || prepared.Status != "prepared" || prepared.Ticket == "" || prepared.Bytes != uint64(len(input)) || target.accepted.Load() != 0 {
		t.Fatal("large preparation failed or invoked SSH")
	}
	header.Ticket = prepared.Ticket
	status, delivered := post(apptransport.TextStreamExecutePath, encode(header, input))
	if status != http.StatusOK || delivered.Status != "received" || target.writes.Load() != 1 {
		t.Fatal("root-granted private stream did not complete authenticated SSH delivery")
	}
	stored, err := os.ReadFile(target.path)
	want := append(append([]byte(nil), input[:len(input)-len(placeholder)]...), []byte(connectedSecret)...)
	if err != nil || len(stored) <= 1<<20 || !bytes.Equal(stored, want) {
		t.Fatal("large SSH consumer bytes did not match the exact hydrated template")
	}
	clear(stored)
	clear(want)
	accepted := target.accepted.Load()
	if status, reply := post(apptransport.TextStreamExecutePath, encode(header, input)); status != http.StatusOK || reply.Status != "withheld" || target.accepted.Load() != accepted {
		t.Fatal("stream ticket replay contacted SSH")
	}
}
