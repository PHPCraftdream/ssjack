//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const reverseLateChild = "SSJACK_TEXT_REVERSE_LATE_CHILD"

func TestTextReverseLateConnected(t *testing.T) {
	if os.Getenv(connectedGate) != "1" {
		t.Skip("CI acceptance gate disabled")
	}
	if os.Getenv(reverseLateChild) == "1" {
		reverseLateConnectedChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("connected acceptance parent requires root")
	}

	grantR, grantW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer grantR.Close()
	ackR, ackW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ackW.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err = grantR.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestTextReverseLateConnected$")
	cmd.Dir = "/tmp"
	cmd.ExtraFiles = []*os.File{grantW, ackR}
	cmd.Env = append(os.Environ(), connectedGate+"=1", reverseLateChild+"=1", "TMPDIR=/tmp")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	log := &boundedChildLog{}
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	stop := func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			waited = true
		}
	}
	defer stop()
	defer func() {
		if t.Failed() {
			stop()
			t.Logf("child diagnostics:\n%s", log.String())
		}
	}()
	_ = grantW.Close()
	_ = ackR.Close()

	var grant declarativeauthority.TextAdapterGrant
	if err = json.NewDecoder(grantR).Decode(&grant); err != nil {
		stop()
		t.Fatalf("read child grant: %v", err)
	}
	if grant.RecipientUID != 65534 {
		stop()
		t.Fatalf("grant recipient UID=%d", grant.RecipientUID)
	}
	if err = declarativeauthority.LoadSetup(); err != nil {
		if err = declarativeauthority.Setup(); err != nil {
			stop()
			t.Fatalf("setup: %v", err)
		}
	}
	if err = declarativeauthority.RegisterTextAdapter(grant); err != nil {
		stop()
		t.Fatalf("register reverse grant: %v", err)
	}
	defer declarativeauthority.RevokeTextAdapter(grant.ID)
	if _, err = ackW.Write([]byte{1}); err != nil {
		stop()
		t.Fatalf("ack grant: %v", err)
	}
	var dispatched [1]byte
	if _, err = io.ReadFull(grantR, dispatched[:]); err != nil || dispatched[0] != 1 {
		stop()
		t.Fatalf("wait for runner dispatch: byte=%d err=%v", dispatched[0], err)
	}
	if err = declarativeauthority.RevokeTextAdapter(grant.ID); err != nil {
		stop()
		t.Fatalf("revoke during runner: %v", err)
	}
	if _, err = ackW.Write([]byte{2}); err != nil {
		stop()
		t.Fatalf("ack revocation: %v", err)
	}
	if err = cmd.Wait(); err != nil {
		waited = true
		t.Fatalf("child acceptance: %v\nchild diagnostics:\n%s", err, log.String())
	}
	waited = true
}

func reverseLateConnectedChild(t *testing.T) {
	grantPipe, ackPipe := os.NewFile(3, "grant"), os.NewFile(4, "ack")
	if grantPipe == nil || ackPipe == nil {
		t.Fatal("missing grant pipes")
	}
	defer grantPipe.Close()
	defer ackPipe.Close()
	installation, grant, placeholder := appstorecrypto.TextAdapterFixture(t)
	if err := ackPipe.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	grant.Mode = "reverse-copy-v1"
	if err := json.NewEncoder(grantPipe).Encode(grant); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(ackPipe, ack[:]); err != nil || ack[0] != 1 {
		t.Fatalf("parent grant acknowledgement: byte=%d err=%v", ack[0], err)
	}

	var calls atomic.Int32
	runner := remote.StreamRunner(func(_ context.Context, profile, command string, _ io.Reader, stdout, stderr io.Writer) (int, error) {
		calls.Add(1)
		if profile != grant.Profile || command != grant.Command {
			t.Error("unexpected runner profile or command")
		}
		if _, err := grantPipe.Write([]byte{1}); err != nil {
			return 1, err
		}
		var release [1]byte
		if _, err := io.ReadFull(ackPipe, release[:]); err != nil || release[0] != 2 {
			t.Error("root revocation acknowledgement failed")
			return 1, err
		}
		if _, err := stdout.Write([]byte(connectedSecret)); err != nil {
			return 1, err
		}
		if _, err := stderr.Write([]byte(connectedSecret)); err != nil {
			return 1, err
		}
		return 0, nil
	})
	adapter, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
	if err != nil {
		t.Fatalf("construct adapter: %v", err)
	}
	defer adapter.Close()
	server, err := apptransport.ListenWithReverseTextAdapter(context.Background(), grant.Profile, runner, adapter)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer server.Close()
	bootstrap := server.Bootstrap()
	tlsConfig, err := wire.ClientTLS(bootstrap.Pin)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 20 * time.Second}
	defer client.CloseIdleConnections()

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "text_reverse_copy",
			"arguments": map[string]any{
				"operation_id": "AAECAwQFBgcICQoLDA0ODw",
				"file":         grant.File,
				"mode":         grant.Mode,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	doRequest := func() []byte {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, bootstrap.Endpoint, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("MCP-Protocol-Version", "2025-06-18")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 25<<20))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("HTTP status=%d", response.StatusCode)
		}
		if bytes.Contains(data, []byte(connectedSecret)) {
			t.Fatal("raw response disclosed synthetic secret")
		}
		return data
	}
	data := doRequest()
	var result struct {
		Result struct {
			Structured struct {
				Status string  `json:"status"`
				Text   *string `json:"text"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Result.Structured.Status != "unknown" || result.Result.Structured.Text != nil {
		t.Fatalf("late-revoked outcome: status=%q hasText=%t", result.Result.Structured.Status, result.Result.Structured.Text != nil)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("runner calls=%d, want 1", got)
	}
	replay := doRequest()
	if bytes.Contains(replay, []byte(connectedSecret)) {
		t.Fatal("raw replay disclosed synthetic secret")
	}
	if err = json.Unmarshal(replay, &result); err != nil {
		t.Fatalf("decode replay: %v", err)
	}
	if result.Result.Structured.Status != "withheld" || result.Result.Structured.Text != nil || calls.Load() != 1 {
		t.Fatalf("replay: status=%q hasText=%t runner calls=%d", result.Result.Structured.Status, result.Result.Structured.Text != nil, calls.Load())
	}
	if bytes.Contains(data, []byte(placeholder)) {
		t.Fatal("unexpected placeholder in unknown response")
	}
}
