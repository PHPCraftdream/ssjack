//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func reverseConnectedEffectEdges(t *testing.T, installation *appstorecrypto.Installation, grant declarativeauthority.TextAdapterGrant) {
	t.Helper()

	t.Run("caller deadline and cancellation", func(t *testing.T) {
		caller, cancelCaller := context.WithDeadline(context.Background(), time.Now().Add(10*time.Second))
		defer cancelCaller()

		var calls atomic.Int32
		runner := remote.StreamRunner(func(runctx context.Context, _ string, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
			calls.Add(1)
			want, ok := caller.Deadline()
			got, hasDeadline := runctx.Deadline()
			if !ok || !hasDeadline || !got.Equal(want) {
				t.Errorf("runner deadline=%v present=%v, caller deadline=%v present=%v", got, hasDeadline, want, ok)
			}
			cancelCaller()
			_, _ = stdout.Write([]byte(connectedSecret))
			return 0, nil
		})
		adapter, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
		if err != nil {
			t.Fatalf("construct adapter: %v", err)
		}
		defer adapter.Close()

		outcome := adapter.ReverseCopy(caller, "AAECAwQFBgcICQoLDA0ODw", grant.File)
		if outcome.Status != appstorecrypto.DeliveryUnknown || outcome.Text != nil || calls.Load() != 1 {
			t.Fatalf("status=%d hasText=%t runner calls=%d", outcome.Status, outcome.Text != nil, calls.Load())
		}
		replay := adapter.ReverseCopy(context.Background(), "AAECAwQFBgcICQoLDA0ODw", grant.File)
		if replay.Status != appstorecrypto.DeliveryWithheld || replay.Text != nil || calls.Load() != 1 {
			t.Fatalf("replay status=%d hasText=%t runner calls=%d", replay.Status, replay.Text != nil, calls.Load())
		}
	})

	t.Run("late pointer mutation", func(t *testing.T) {
		pointerPath := filepath.Join(grant.StorePath, "pointer.bin")
		original, err := os.ReadFile(pointerPath)
		if err != nil {
			t.Fatalf("read pointer: %v", err)
		}
		if len(original) != 64 {
			t.Fatalf("pointer length=%d, want 64", len(original))
		}
		pointer, err := os.OpenFile(pointerPath, os.O_WRONLY, 0)
		if err != nil {
			t.Fatalf("open pointer: %v", err)
		}
		defer func() {
			if _, restoreErr := pointer.WriteAt(original[:1], 0); restoreErr != nil {
				t.Errorf("restore pointer: %v", restoreErr)
			}
			if closeErr := pointer.Close(); closeErr != nil {
				t.Errorf("close pointer: %v", closeErr)
			}
		}()

		var calls atomic.Int32
		runner := remote.StreamRunner(func(_ context.Context, _ string, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
			calls.Add(1)
			flipped := []byte{original[0] ^ 0xff}
			if n, writeErr := pointer.WriteAt(flipped, 0); writeErr != nil || n != 1 {
				t.Error("fixture pointer mutation failed")
				return 1, writeErr
			}
			_, _ = stdout.Write([]byte(connectedSecret))
			return 0, nil
		})
		adapter, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
		if err != nil {
			t.Fatalf("construct adapter: %v", err)
		}
		defer adapter.Close()

		outcome := adapter.ReverseCopy(context.Background(), "AAECAwQFBgcICQoLDA0ODw", grant.File)
		if outcome.Status != appstorecrypto.DeliveryUnknown || outcome.Text != nil || calls.Load() != 1 {
			t.Fatalf("status=%d hasText=%t runner calls=%d", outcome.Status, outcome.Text != nil, calls.Load())
		}
		replay := adapter.ReverseCopy(context.Background(), "AAECAwQFBgcICQoLDA0ODw", grant.File)
		if replay.Status != appstorecrypto.DeliveryWithheld || replay.Text != nil || calls.Load() != 1 {
			t.Fatalf("replay status=%d hasText=%t runner calls=%d", replay.Status, replay.Text != nil, calls.Load())
		}
	})

	t.Run("lost HTTP response after cancellation", func(t *testing.T) {
		parent, cancelParent := context.WithCancel(context.Background())
		var calls atomic.Int32
		started := make(chan struct{})
		runnerDone := make(chan struct{})
		runner := remote.StreamRunner(func(runctx context.Context, _ string, _ string, _ io.Reader, stdout, stderr io.Writer) (int, error) {
			calls.Add(1)
			close(started)
			<-runctx.Done()
			_, _ = stdout.Write([]byte(connectedSecret))
			_, _ = stderr.Write([]byte(connectedSecret))
			close(runnerDone)
			return 0, nil
		})
		adapter, err := appstorecrypto.NewReverseTextAdapter(parent, installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
		if err != nil {
			cancelParent()
			t.Fatalf("construct adapter: %v", err)
		}
		server, err := apptransport.ListenWithReverseTextAdapter(parent, grant.Profile, runner, adapter)
		if err != nil {
			cancelParent()
			_ = adapter.Close()
			t.Fatalf("listen: %v", err)
		}
		defer func() {
			cancelParent()
			server.Close()
			_ = adapter.Close()
		}()

		bootstrap := server.Bootstrap()
		config, err := wire.ClientTLS(bootstrap.Pin)
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: config,
			},
			Timeout: 20 * time.Second,
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

		doRequest := func(ctx context.Context) ([]byte, error) {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, bootstrap.Endpoint, bytes.NewReader(body))
			if reqErr != nil {
				return nil, reqErr
			}
			req.Header.Set("Authorization", "Bearer "+bootstrap.Token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("MCP-Protocol-Version", "2025-06-18")
			resp, doErr := client.Do(req)
			if doErr != nil {
				return nil, doErr
			}
			defer resp.Body.Close()
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			return data, readErr
		}

		type response struct {
			Result struct {
				Structured struct {
					Status string  `json:"status"`
					Text   *string `json:"text"`
				} `json:"structuredContent"`
			} `json:"result"`
		}

		requestCtx, cancelRequest := context.WithCancel(context.Background())
		type requestResult struct {
			data []byte
			err  error
		}
		result := make(chan requestResult, 1)
		defer cancelRequest()
		go func() {
			data, err := doRequest(requestCtx)
			result <- requestResult{data: data, err: err}
		}()
		deadline := time.NewTimer(10 * time.Second)
		select {
		case <-started:
		case <-deadline.C:
			cancelRequest()
			t.Fatal("runner did not start before timeout")
		}
		deadline.Stop()
		cancelRequest()
		select {
		case got := <-result:
			if got.err == nil || len(got.data) != 0 || bytes.Contains(got.data, []byte(connectedSecret)) {
				t.Fatal("canceled request unexpectedly exposed a response")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("cancelled HTTP request did not finish")
		}
		select {
		case <-runnerDone:
		case <-time.After(10 * time.Second):
			t.Fatal("runner did not finish after cancellation")
		}
		if calls.Load() != 1 {
			t.Fatalf("runner calls=%d", calls.Load())
		}

		replayCtx, cancelReplay := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelReplay()
		data, err := doRequest(replayCtx)
		if err != nil {
			t.Fatalf("replay request: %v", err)
		}
		if bytes.Contains(data, []byte(connectedSecret)) {
			t.Fatal("replay response disclosed synthetic secret")
		}
		var decoded response
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("decode replay: %v", err)
		}
		if decoded.Result.Structured.Status != "withheld" || decoded.Result.Structured.Text != nil || calls.Load() != 1 {
			t.Fatalf("replay status=%s hasText=%t runner calls=%d", decoded.Result.Structured.Status, decoded.Result.Structured.Text != nil, calls.Load())
		}
	})
}
