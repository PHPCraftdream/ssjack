//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerresource"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func verifyConnectedOwnerConsumer(t *testing.T, grant declarativeauthority.TextAdapterGrant) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	password := []byte("synthetic connected owner database")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "owner.ktav")
	v := vault.NewDirectory()
	defer v.Close()
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	manager, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Discard()
	master := []byte("synthetic installation writer fixture")
	defer clear(master)
	if err := manager.Link(grant.StorePath, master); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	runner := remote.StreamRunner(func(_ context.Context, profile, command string, input io.Reader, stdout, stderr io.Writer) (int, error) {
		calls.Add(1)
		value, readErr := io.ReadAll(input)
		defer clear(value)
		if profile != grant.Profile || command != grant.Command || stdout != io.Discard || stderr != io.Discard || !bytes.Equal(value, []byte("before "+connectedSecret+" after")) {
			t.Error("borrowed consumer changed its frozen private delivery scope")
		}
		return 0, readErr
	})
	for _, mode := range []string{"reverse-copy-v1", "hydrate-stream-v2", "reverse-copy-stream-v2"} {
		borrower, err := manager.ServeText(ctx, ownerresource.TextRequest{Mode: mode, GrantID: connectedVariantID(grant.ID, "shared-"+mode), Profile: grant.Profile, CredentialDigest: grant.CredentialSHA256, Runner: runner})
		if err != nil {
			t.Fatal("fixed-mode borrowed consumer admission:", err)
		}
		if err := borrower.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	request := ownerresource.TextRequest{Mode: grant.Mode, GrantID: grant.ID, Profile: grant.Profile, CredentialDigest: grant.CredentialSHA256, Runner: runner}
	first, err := manager.ServeText(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.ServeText(ctx, request)
	if err != nil {
		t.Fatal("second borrower competed for the installation lease:", err)
	}
	if competing, openErr := appstoreentry.Open(grant.StorePath); openErr == nil {
		_ = competing.Close()
		t.Fatal("consumer admission lost exclusive installation ownership")
	}
	if got := postOwnerText(t, first.Bootstrap(), grant); got != "received" || calls.Load() != 1 {
		t.Fatal("borrowed consumer did not deliver its exact frozen reference")
	}
	if err := first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.Submit(vault.OwnerChange{Action: "add", Name: "new-value", MediaType: "text/plain", Value: []byte("synthetic later owner value")}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal("editing with an unused live consumer failed:", err)
	}
	if got := postOwnerText(t, second.Bootstrap(), grant); got != "withheld" || calls.Load() != 1 {
		t.Fatal("old unused grant adopted the newer committed snapshot")
	}
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(ctx); err != nil {
		t.Fatal("parent shutdown did not join its borrowed consumer")
	}
	reopened, err := appstoreentry.Open(grant.StorePath)
	if err != nil {
		t.Fatal("joined owner shutdown retained the installation lease:", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func postOwnerText(t *testing.T, bootstrap apptransport.Bootstrap, grant declarativeauthority.TextAdapterGrant) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "text_hydrate", "arguments": map[string]any{
			"operation_id": "AAECAwQFBgcICQoLDA0ODw", "file": grant.File,
			"mode": grant.Mode, "template": "before " + grant.References[0] + " after",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := wire.ClientTLS(bootstrap.Pin)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodPost, bootstrap.Endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK || bytes.Contains(raw, []byte(connectedSecret)) || bytes.Contains(raw, []byte("synthetic later owner value")) {
		t.Fatal("borrowed consumer returned invalid or private model-visible output")
	}
	var reply struct {
		Result struct {
			StructuredContent struct {
				Status string `json:"status"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		t.Fatal("invalid borrowed consumer response")
	}
	return reply.Result.StructuredContent.Status
}

func registerOwnerConsumerGrants(t *testing.T, grant declarativeauthority.TextAdapterGrant) {
	t.Helper()
	for _, mode := range []string{"reverse-copy-v1", "hydrate-stream-v2", "reverse-copy-stream-v2"} {
		variant := grant
		variant.ID, variant.Mode = connectedVariantID(grant.ID, "shared-"+mode), mode
		register, revoke := declarativeauthority.RegisterTextAdapter, declarativeauthority.RevokeTextAdapter
		if strings.HasSuffix(mode, "stream-v2") {
			register, revoke = declarativeauthority.RegisterTextStream, declarativeauthority.RevokeTextStream
		}
		if err := register(variant); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = revoke(variant.ID) })
	}
}
