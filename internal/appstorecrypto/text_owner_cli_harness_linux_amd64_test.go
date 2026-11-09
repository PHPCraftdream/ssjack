//go:build linux && amd64

package appstorecrypto_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestTextOwnerHarnessChild(t *testing.T) {
	if os.Getenv("SSJACK_TEXT_OWNER_HARNESS_CHILD") != "1" {
		t.Skip("owned actual text CLI harness only")
	}
	var args []string
	for index, value := range os.Args {
		if value == "--" {
			args = os.Args[index+1:]
			break
		}
	}
	if len(args) != 3 || (args[0] != "received" && args[0] != "withheld") {
		t.Fatal("invalid text CLI harness metadata")
	}
	bootstrap := apptransport.Bootstrap{Endpoint: os.Getenv(apptransport.EnvEndpoint), Token: os.Getenv(apptransport.EnvToken), Pin: os.Getenv(apptransport.EnvPin)}
	if bootstrap.Endpoint == "" || bootstrap.Token == "" || bootstrap.Pin == "" {
		t.Fatal("actual text CLI did not privately bootstrap its harness")
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintln(os.Stdout, "TEXT-OWNER-HARNESS-READY")
	command, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(command) != "h" {
		t.Fatal("text CLI harness hydration decision was missing")
	}
	status := textOwnerHarnessHydrate(t, bootstrap, args[1], args[2])
	if status != args[0] {
		t.Fatal("actual text CLI returned an unexpected pinned-grant outcome")
	}
	fmt.Fprintln(os.Stdout, "TEXT-OWNER-HYDRATE-"+status)
	command, err = reader.ReadString('\n')
	if err != nil || strings.TrimSpace(command) != "q" {
		t.Fatal("text CLI harness close decision was missing")
	}
}

func textOwnerHarnessHydrate(t *testing.T, bootstrap apptransport.Bootstrap, file, reference string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "text_hydrate", "arguments": map[string]any{
			"operation_id": "AAECAwQFBgcICQoLDA0ODw", "file": file, "mode": "hydrate-v1", "template": "before " + reference + " after",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := wire.ClientTLS(bootstrap.Pin)
	if err != nil {
		t.Fatal("text CLI harness rejected the private TLS pin")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: configuration}, Timeout: 20 * time.Second}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, bootstrap.Endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal("invalid private text CLI endpoint")
	}
	request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-06-18")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("text CLI harness could not call its private transport")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	defer clear(data)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("text CLI transport did not return a bounded successful response")
	}
	for _, private := range []string{connectedSecret, textOwnerLaterValue, textOwnerMaster, textOwnerSSHPassword, pairShortSecret} {
		if bytes.Contains(data, []byte(private)) {
			t.Fatal("text CLI transport returned private data to its harness")
		}
	}
	var reply struct {
		Result struct {
			StructuredContent struct {
				Status string `json:"status"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &reply) != nil {
		t.Fatal("text CLI transport returned invalid outcome metadata")
	}
	return reply.Result.StructuredContent.Status
}
