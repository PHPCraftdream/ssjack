//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const (
	connectedGate   = "SSJACK_TEXT_ADAPTER_CI_ACCEPTANCE"
	connectedChild  = "SSJACK_TEXT_ADAPTER_CONNECTED_CHILD"
	connectedSecret = "synthetic-connected-secret"
	maxChildLog     = 16 << 10
)

type boundedChildLog struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (l *boundedChildLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	remaining := maxChildLog - len(l.data)
	if remaining > 0 {
		if len(p) > remaining {
			l.data = append(l.data, p[:remaining]...)
		} else {
			l.data = append(l.data, p...)
		}
	}
	if len(p) > remaining {
		l.truncated = true
	}
	return len(p), nil
}

func (l *boundedChildLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := string(l.data)
	if l.truncated {
		result += "\n[child diagnostics truncated at 16 KiB]"
	}
	return result
}

func TestBoundedSyntheticChildDiagnostics(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		log := &boundedChildLog{}
		if n, err := log.Write([]byte("small diagnostic")); err != nil || n != len("small diagnostic") {
			t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len("small diagnostic"))
		}
		if got := log.String(); got != "small diagnostic" {
			t.Fatalf("String() = %q, want %q", got, "small diagnostic")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		log := &boundedChildLog{}
		payload := strings.Repeat("x", maxChildLog+20)
		if n, err := log.Write([]byte(payload)); err != nil || n != len(payload) {
			t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(payload))
		}
		if n, err := log.Write([]byte("tail")); err != nil || n != len("tail") {
			t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len("tail"))
		}
		log.mu.Lock()
		stored := len(log.data)
		log.mu.Unlock()
		if stored != maxChildLog {
			t.Fatalf("stored data length = %d, want %d", stored, maxChildLog)
		}
		got := log.String()
		if !strings.Contains(got, "[child diagnostics truncated at 16 KiB]") {
			t.Fatalf("String() missing truncation marker")
		}
		if strings.Contains(got, "tail") {
			t.Fatalf("String() contains data written after limit")
		}
	})
}

func TestTextAdapterConnected(t *testing.T) {
	if os.Getenv(connectedGate) != "1" {
		t.Skip("CI acceptance gate is disabled")
	}
	if os.Getenv(connectedChild) == "1" {
		connectedTextChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("connected acceptance parent requires root")
	}

	grantR, grantW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer grantR.Close()
	defer ackW.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestTextAdapterConnected$")
	cmd.Dir = "/tmp"
	cmd.ExtraFiles = []*os.File{grantW, ackR}
	cmd.Env = append(os.Environ(), connectedGate+"=1", connectedChild+"=1", "TMPDIR=/tmp")
	childLog := &boundedChildLog{}
	cmd.Stdout = childLog
	cmd.Stderr = childLog
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    65534,
			Gid:    65534,
			Groups: []uint32{},
		},
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	stopAndWait := func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			waited = true
		}
	}
	defer stopAndWait()
	defer func() {
		if t.Failed() {
			stopAndWait()
			t.Logf("synthetic child diagnostics:\n%s", childLog.String())
		}
	}()
	grantW.Close()
	ackR.Close()

	var grant declarativeauthority.TextAdapterGrant
	if err = json.NewDecoder(grantR).Decode(&grant); err != nil {
		stopAndWait()
		t.Fatal(err)
	}
	if grant.RecipientUID != 65534 {
		stopAndWait()
		t.Fatalf("grant recipient UID=%d, want 65534", grant.RecipientUID)
	}
	if err = declarativeauthority.LoadSetup(); err != nil {
		if err = declarativeauthority.Setup(); err != nil {
			stopAndWait()
			t.Fatal(err)
		}
	}
	if err = declarativeauthority.RegisterTextAdapter(grant); err != nil {
		stopAndWait()
		t.Fatal(err)
	}
	defer func() {
		_ = declarativeauthority.RevokeTextAdapter(grant.ID)
	}()

	variants := make(map[string]declarativeauthority.TextAdapterGrant)
	register := func(label string, mutate func(*declarativeauthority.TextAdapterGrant)) {
		variant := grant
		variant.References = append([]string(nil), grant.References...)
		variant.ID = connectedVariantID(grant.ID, label)
		mutate(&variant)
		if err := declarativeauthority.ValidateTextAdapterGrant(variant, time.Now()); err != nil {
			t.Fatalf("invalid %s variant: %v", label, err)
		}
		if err := declarativeauthority.RegisterTextAdapter(variant); err != nil {
			t.Fatalf("register %s: %v", label, err)
		}
		variants[label] = variant
		t.Cleanup(func() {
			_ = declarativeauthority.RevokeTextAdapter(variant.ID)
		})
	}
	register("wrong-hash", func(g *declarativeauthority.TextAdapterGrant) {
		g.EncodedHash = strings.Repeat("0", 64)
	})
	register("wrong-reference", func(g *declarativeauthority.TextAdapterGrant) {
		ref, err := appstoreplaceholder.Parse([]byte(g.References[0]))
		if err != nil {
			t.Fatal(err)
		}
		wrong, err := appstoreref.New(ref.StoreID(), [16]byte{99}, ref.VersionID(), ref.SnapshotID())
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := appstoreplaceholder.Encode(wrong)
		if err != nil {
			t.Fatal(err)
		}
		g.References[0] = string(encoded)
	})
	register("revoked", func(g *declarativeauthority.TextAdapterGrant) {})
	expired := grant
	expired.ID = connectedVariantID(grant.ID, "expired")
	expired.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	if err = declarativeauthority.RegisterTextAdapter(expired); err == nil {
		stopAndWait()
		t.Fatal("expired grant registered")
	}
	if err = declarativeauthority.RevokeTextAdapter(variants["revoked"].ID); err != nil {
		stopAndWait()
		t.Fatal(err)
	}
	if _, err = ackW.Write([]byte{1}); err != nil {
		stopAndWait()
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("child acceptance: %v\nsynthetic child diagnostics:\n%s", err, childLog.String())
	}
}

func connectedVariantID(base, label string) string {
	digest := sha256.Sum256([]byte(base + label))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

func connectedTextChild(t *testing.T) {
	grantFD := os.NewFile(3, "grant")
	ackFD := os.NewFile(4, "ack")
	if grantFD == nil || ackFD == nil {
		t.Fatal("missing grant pipes")
	}
	defer grantFD.Close()
	defer ackFD.Close()

	installation, grant, placeholder := appstorecrypto.TextAdapterFixture(t)
	grant.RecipientUID = os.Geteuid()
	if err := json.NewEncoder(grantFD).Encode(grant); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ackFD, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	// Verify the unprivileged child observes the grant registered by the parent.
	loaded, err := declarativeauthority.LoadTextAdapter(grant.ID, os.Geteuid(), time.Now())
	if err != nil || loaded.ID != grant.ID || loaded.Profile != grant.Profile || loaded.EncodedHash != grant.EncodedHash || len(loaded.References) != len(grant.References) || loaded.References[0] != grant.References[0] {
		t.Fatal("registered grant did not match the synthetic child grant")
	}
	credentialDigest := grant.CredentialSHA256
	credential := "synthetic-approved-consumer"
	var calls atomic.Int32
	digest := sha256.Sum256([]byte(credential))
	if hex.EncodeToString(digest[:]) != credentialDigest {
		t.Fatal("fixture credential digest mismatch")
	}
	runner := remote.StreamRunner(func(_ context.Context, profile, command string, input io.Reader, stdout, stderr io.Writer) (int, error) {
		calls.Add(1)
		if profile != grant.Profile || command != grant.Command || stdout != io.Discard || stderr != io.Discard {
			t.Error("unexpected runner binding")
		}
		got, err := io.ReadAll(input)
		if !bytes.Equal(got, []byte("before "+connectedSecret+" after")) {
			t.Error("runner input mismatch")
		}
		_, _ = stdout.Write([]byte(connectedSecret))
		_, _ = stderr.Write([]byte(connectedSecret))
		return 0, err
	})
	newAdapter := func(profile, cred string) (*appstorecrypto.TextAdapter, error) {
		return appstorecrypto.NewTextAdapter(context.Background(), installation, grant.ID, profile, cred, runner)
	}
	if _, err = newAdapter(grant.Profile, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong credential accepted")
	}
	if _, err = newAdapter("wrong-profile", credentialDigest); err == nil {
		t.Fatal("wrong profile accepted")
	}
	missing := grant
	missing.ID = "AAAAAAAAAAAAAAAAAAAAAA"
	if _, err = appstorecrypto.NewTextAdapter(context.Background(), installation, missing.ID, grant.Profile, credentialDigest, runner); err == nil {
		t.Fatal("missing grant accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid constructor invoked runner")
	}
	for _, label := range []string{"wrong-hash", "wrong-reference"} {
		variantID := connectedVariantID(grant.ID, label)
		adapter, adapterErr := appstorecrypto.NewTextAdapter(context.Background(), installation, variantID, grant.Profile, credentialDigest, runner)
		if adapterErr != nil {
			t.Fatalf("%s constructor: %v", label, adapterErr)
		}
		outcome := adapter.Hydrate(context.Background(), "AAECAwQFBgcICQoLDA0ODw", grant.File, []byte("before "+placeholder+" after"))
		_ = adapter.Close()
		if outcome.Status != appstorecrypto.DeliveryWithheld || calls.Load() != 0 {
			t.Fatalf("%s was not withheld before execution", label)
		}
	}
	if _, err = appstorecrypto.NewTextAdapter(context.Background(), installation, connectedVariantID(grant.ID, "revoked"), grant.Profile, credentialDigest, runner); err == nil {
		t.Fatal("revoked grant accepted")
	}
	adapter, err := newAdapter(grant.Profile, credentialDigest)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	cancelledctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledOutcome := adapter.Hydrate(cancelledctx, "AAECAwQFBgcICQoLDA0ODw", grant.File, []byte("before "+placeholder+" after"))
	if cancelledOutcome.Status != appstorecrypto.DeliveryWithheld || calls.Load() != 0 {
		t.Fatal("cancelled request was not withheld before execution")
	}
	server, err := apptransport.ListenWithTextAdapter(context.Background(), grant.Profile, runner, adapter)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	bootstrap := server.Bootstrap()
	config, err := wire.ClientTLS(bootstrap.Pin)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: config},
		Timeout:   10 * time.Second,
	}
	defer client.CloseIdleConnections()
	post := func(file, selected string) (*http.Response, []byte) {
		body, marshalErr := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "text_hydrate",
				"arguments": map[string]any{
					"operation_id": "AAECAwQFBgcICQoLDA0ODw",
					"file":         file,
					"mode":         grant.Mode,
					"template":     selected,
				},
			},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		req, reqErr := http.NewRequest(http.MethodPost, bootstrap.Endpoint, bytes.NewReader(body))
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Header.Set("Authorization", "Bearer "+bootstrap.Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		resp, doErr := client.Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		return resp, data
	}
	assertRejected := func(file, selected string) {
		_, data := post(file, selected)
		var envelope struct {
			Error json.RawMessage `json:"error"`
			Result struct {
				IsError           bool `json:"isError"`
				StructuredContent struct {
					Status string `json:"status"`
				} `json:"structuredContent"`
			} `json:"result"`
		}
		if json.Unmarshal(data, &envelope) != nil {
			t.Fatal("invalid rejection JSON")
		}
		if len(envelope.Error) == 0 && !envelope.Result.IsError && envelope.Result.StructuredContent.Status != "withheld" {
			t.Fatal("request was not refused")
		}
		if bytes.Contains(data, []byte(connectedSecret)) {
			t.Fatal("secret in refusal")
		}
	}
	assertRejected(grant.File+".wrong", "before "+placeholder+" after")
	assertRejected(grant.File, strings.Repeat("x", 33<<10))
	if calls.Load() != 0 {
		t.Fatal("rejected request invoked runner")
	}
	resp, data := post(grant.File, "before "+placeholder+" after")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("positive request status=%d", resp.StatusCode)
	}
	var envelope struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		t.Fatal("invalid positive response JSON")
	}
	found := false
	for _, item := range envelope.Result.Content {
		var result struct {
			Status string `json:"status"`
		}
		if json.Unmarshal([]byte(item.Text), &result) == nil && result.Status == "received" {
			found = true
		}
	}
	if !found || bytes.Contains(data, []byte(connectedSecret)) {
		t.Fatal("positive result missing structured received status or disclosed secret")
	}
	if calls.Load() != 1 {
		t.Fatalf("runner calls=%d, want 1", calls.Load())
	}
	resp, data = post(grant.File, "before "+placeholder+" after")
	if resp.StatusCode != http.StatusOK || calls.Load() != 1 || bytes.Contains(data, []byte(connectedSecret)) {
		t.Fatal("replay was not safely withheld")
	}
	var replay struct {
		Result struct {
			StructuredContent struct {
				Status string `json:"status"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &replay) != nil || replay.Result.StructuredContent.Status != "withheld" {
		t.Fatal("replay response did not report withheld")
	}
}
