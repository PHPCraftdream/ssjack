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

const reverseExpiryChild = "SSJACK_TEXT_REVERSE_EXPIRY_CHILD"

func TestTextReverseExpiryConnected(t *testing.T) {
	if os.Getenv(connectedGate) != "1" {
		t.Skip("CI acceptance gate disabled")
	}
	if os.Getenv(reverseExpiryChild) == "1" {
		reverseExpiryConnectedChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("connected expiry acceptance parent requires root")
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err = grantR.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestTextReverseExpiryConnected$")
	cmd.Dir = "/tmp"
	cmd.ExtraFiles = []*os.File{grantW, ackR}
	cmd.Env = append(os.Environ(), connectedGate+"=1", reverseExpiryChild+"=1", "TMPDIR=/tmp")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    65534,
			Gid:    65534,
			Groups: []uint32{},
		},
	}
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
	if grant.Mode != "reverse-copy-v1" {
		stop()
		t.Fatalf("unexpected grant mode %q", grant.Mode)
	}
	// This long-lived grant is only for the child's real positive control. The
	// short-lived grant is registered after that control has completed.
	baseID := grant.ID
	control := grant
	control.ID = connectedVariantID(baseID, "expiry-control")
	control.ExpiresAt = time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	if err = declarativeauthority.RegisterTextAdapter(control); err != nil {
		stop()
		t.Fatalf("register positive-control grant: %v", err)
	}
	defer declarativeauthority.RevokeTextAdapter(control.ID)
	if err = json.NewEncoder(ackW).Encode(control); err != nil {
		stop()
		t.Fatalf("send control grant: %v", err)
	}
	var ready [1]byte
	if _, err = io.ReadFull(grantR, ready[:]); err != nil || ready[0] != 1 {
		stop()
		t.Fatalf("read positive-control readiness: byte=%d err=%v", ready[0], err)
	}
	grant.ID = connectedVariantID(baseID, "expiry-live")
	grant.ExpiresAt = time.Now().Add(15 * time.Second).UTC().Format(time.RFC3339)
	if err = declarativeauthority.RegisterTextAdapter(grant); err != nil {
		stop()
		t.Fatalf("register active reverse grant: %v", err)
	}
	defer declarativeauthority.RevokeTextAdapter(grant.ID)
	if err = json.NewEncoder(ackW).Encode(grant); err != nil {
		stop()
		t.Fatalf("send expiry grant: %v", err)
	}
	if err = cmd.Wait(); err != nil {
		waited = true
		t.Fatalf("child acceptance: %v\nchild diagnostics:\n%s", err, log.String())
	}
	waited = true
}

func reverseConnectedExpiry(t *testing.T, installation *appstorecrypto.Installation, grant declarativeauthority.TextAdapterGrant) {
	t.Helper()

	var calls atomic.Int32
	runner := remote.StreamRunner(func(runctx context.Context, _, _ string, _ io.Reader, stdout, stderr io.Writer) (int, error) {
		calls.Add(1)
		got, ok := runctx.Deadline()
		expected, err := time.Parse(time.RFC3339, grant.ExpiresAt)
		if err != nil || !ok || !got.Equal(expected) {
			t.Errorf("runner deadline=%v present=%v expected=%v", got, ok, expected)
		}
		if !expected.After(time.Now()) {
			t.Error("runner dispatched after grant expiry")
		}
		<-runctx.Done()
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
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   25 * time.Second,
	}
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
		expires, _ := time.Parse(time.RFC3339, grant.ExpiresAt)
		ctx, cancel := context.WithDeadline(context.Background(), expires.Add(10*time.Second))
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, bootstrap.Endpoint, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bootstrap.Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		response, err := client.Do(req)
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
	var result struct {
		Result struct {
			Structured struct {
				Status string  `json:"status"`
				Text   *string `json:"text"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	data := doRequest()
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Result.Structured.Status != "unknown" || result.Result.Structured.Text != nil || calls.Load() != 1 {
		t.Fatalf("expired outcome: status=%q text=%v calls=%d", result.Result.Structured.Status, result.Result.Structured.Text, calls.Load())
	}
	replay := doRequest()
	if err = json.Unmarshal(replay, &result); err != nil {
		t.Fatalf("decode replay: %v", err)
	}
	if result.Result.Structured.Status != "withheld" || result.Result.Structured.Text != nil || calls.Load() != 1 {
		t.Fatalf("replay: status=%q text=%v calls=%d", result.Result.Structured.Status, result.Result.Structured.Text, calls.Load())
	}
}

func reverseExpiryConnectedChild(t *testing.T) {
	grantPipe, ackPipe := os.NewFile(3, "grant"), os.NewFile(4, "ack")
	if grantPipe == nil || ackPipe == nil {
		t.Fatal("missing grant pipes")
	}
	defer grantPipe.Close()
	defer ackPipe.Close()
	if err := ackPipe.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	installation, grant, _ := appstorecrypto.TextAdapterFixture(t)
	grant.Mode = "reverse-copy-v1"
	grant.ExpiresAt = time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	if err := json.NewEncoder(grantPipe).Encode(grant); err != nil {
		t.Fatal(err)
	}
	var control declarativeauthority.TextAdapterGrant
	if err := json.NewDecoder(ackPipe).Decode(&control); err != nil {
		t.Fatalf("read positive-control grant: %v", err)
	}
	if err := ackPipe.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reverseExpiryPositiveControl(t, installation, control)
	if _, err := grantPipe.Write([]byte{1}); err != nil {
		t.Fatalf("signal positive-control readiness: %v", err)
	}
	var expiryGrant declarativeauthority.TextAdapterGrant
	if err := json.NewDecoder(ackPipe).Decode(&expiryGrant); err != nil {
		t.Fatalf("read expiry grant: %v", err)
	}
	expires, err := time.Parse(time.RFC3339, expiryGrant.ExpiresAt)
	if err != nil || !expires.After(time.Now()) || time.Until(expires) > 15*time.Second {
		t.Fatalf("invalid short grant expiry %q: %v", expiryGrant.ExpiresAt, err)
	}
	reverseConnectedExpiry(t, installation, expiryGrant)
}
