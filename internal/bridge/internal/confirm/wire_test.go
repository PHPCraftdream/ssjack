// The SDK-client confirmation tests live in rawwire_test.go: an SDK client
// built with mcp.NewClient(impl, nil) auto-fulfils input_required results and
// never reaches its own assertions. Only tests that NEVER elicit remain here.
package confirm_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/bridge/internal/confirm"
	tooltext "github.com/PHPCraftdream/ssjack/internal/bridge/internal/tooltext"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// fakeKeeper answers the keeper operations of the transfer and exec tools
// and records every operation it saw.
type fakeKeeper struct {
	mu  sync.Mutex
	ops []string
	ids int
}

func (k *fakeKeeper) handle(_ context.Context, req wire.Request) wire.Reply {
	k.mu.Lock()
	k.ops = append(k.ops, req.Operation)
	k.mu.Unlock()
	switch req.Operation {
	case "transfer_upload", "transfer_download":
		var input transfer.StartInput
		if wire.Decode(req.Data, &input) != nil {
			return wire.Reply{Error: "invalid transfer arguments"}
		}
		k.mu.Lock()
		k.ids++
		id := fmt.Sprintf("%064x", k.ids)
		k.mu.Unlock()
		return broker.Result(transfer.StartOutput{JobID: id}, nil)
	case "start", "app_start":
		return broker.Result(remote.StartOutput{JobID: strings.Repeat("ab", 32)}, nil)
	case "targets":
		return broker.Result(remote.TargetsOutput{Targets: []string{"allowed"}}, nil)
	}
	return wire.Reply{Error: "unexpected operation"}
}

func (k *fakeKeeper) recorded() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.ops...)
}

// recorder keeps the frames the client read, in order.
type recorder struct {
	mu     sync.Mutex
	frames [][]byte
}

func (r *recorder) add(frame []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, append([]byte(nil), frame...))
}

func (r *recorder) last() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.frames) == 0 {
		return nil
	}
	return r.frames[len(r.frames)-1]
}

// recordingTransport wraps a transport and records every message the client
// reads off it.
type recordingTransport struct {
	inner mcp.Transport
	rec   *recorder
}

func (t *recordingTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	connection, err := t.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &recordingConnection{Connection: connection, rec: t.rec}, nil
}

type recordingConnection struct {
	mcp.Connection
	rec *recorder
}

func (c *recordingConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	message, err := c.Connection.Read(ctx)
	if err != nil {
		return message, err
	}
	if encoded, encodeErr := jsonrpc.EncodeMessage(message); encodeErr == nil {
		c.rec.add(encoded)
	}
	return message, nil
}

// newConfirmBridge serves the full tool registry, with the confirmation
// manager when mgr is not nil, over one authenticated keeper connection.
func newConfirmBridge(t *testing.T, ctx context.Context, keeper *fakeKeeper, now func() time.Time, mgr *confirm.Manager, version string) (*mcp.ClientSession, *recorder) {
	t.Helper()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("5", 64), Token: strings.Repeat("6", 64)}
	server, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, keeper.handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	connection, err := broker.Connect(ctx, server.Endpoint(), server.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	rec := &recorder{}
	mcpServer := tooltext.NewFullServerWithClockAndConfirm(connection, now, mgr)
	serverSession, err := mcpServer.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "confirm-acceptance", Version: "1"}, nil)
	session, err := client.Connect(ctx, &recordingTransport{inner: clientTransport, rec: rec}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session, rec
}

const revision2026 = "2026-07-28"
const revisionLegacy = "2025-11-25"

// formMeta is the per-request `_meta` that positively declares form
// elicitation.
func formMeta() mcp.Meta {
	return mcp.Meta{"io.modelcontextprotocol/clientCapabilities": map[string]any{
		"elicitation": map[string]any{"form": map[string]any{}},
	}}
}

// urlOnlyMeta declares only URL elicitation, which does not qualify.
func urlOnlyMeta() mcp.Meta {
	return mcp.Meta{"io.modelcontextprotocol/clientCapabilities": map[string]any{
		"elicitation": map[string]any{"url": map[string]any{}},
	}}
}

func nullFormMeta() mcp.Meta {
	return mcp.Meta{"io.modelcontextprotocol/clientCapabilities": map[string]any{
		"elicitation": map[string]any{"form": nil},
	}}
}

type callOptions struct {
	meta       mcp.Meta
	responses  mcp.InputResponseMap
	state      string
	overwrite  bool
	target     string
	localField string
}

func uploadArguments(options callOptions) map[string]any {
	arguments := map[string]any{"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin"}
	if options.overwrite {
		arguments["overwrite"] = true
		arguments["confirm"] = true
	}
	if options.target != "" {
		arguments["target"] = options.target
	}
	if options.localField != "" {
		arguments["local"] = options.localField
	}
	return arguments
}

func callTool(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, options callOptions) *mcp.CallToolResult {
	t.Helper()
	var arguments any
	switch name {
	case "remote_upload", "remote_download":
		arguments = uploadArguments(options)
	case "app_exec":
		arguments = map[string]any{"application": "app", "arguments": []string{"status"}, "confirm": true}
	default:
		arguments = map[string]any{}
	}
	params := &mcp.CallToolParams{Name: name, Arguments: arguments, Meta: options.meta, InputResponses: options.responses, RequestState: options.state}
	result, err := session.CallTool(ctx, params)
	if err != nil || result == nil {
		t.Fatalf("%s: %+v, %v", name, result, err)
	}
	return result
}

func answerText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) != 1 {
		t.Fatalf("result is not one content block: %+v", result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is not text: %T", result.Content[0])
	}
	return text.Text
}

// startedUpload is the text of a successful transfer start.
func startedUpload(t *testing.T, result *mcp.CallToolResult, keeper *fakeKeeper) {
	t.Helper()
	started := keeper.recorded()
	if len(started) == 0 {
		t.Fatal("the keeper started no job")
	}
	id := strings.TrimPrefix(strings.TrimSpace(answerText(t, result)), "Started job ")
	id = strings.Fields(id)[0]
	want := "Started job " + id + "\nCheck progress with transfer_status job_id=" + id + "; use wait_seconds 20 to wait for it."
	if got := answerText(t, result); got != want {
		t.Fatalf("the start answered %q, want %q", got, want)
	}
}

// noStateChangingCalls asserts the keeper saw no operation at all.
func noStateChangingCalls(t *testing.T, keeper *fakeKeeper) {
	t.Helper()
	if ops := keeper.recorded(); len(ops) != 0 {
		t.Fatalf("the keeper saw operations: %v", ops)
	}
}

// newConfirmRequest performs one initial eligible call and returns the state
// token of its input_required answer.

func TestConfirmOffByDefaultAndPassthrough(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Run("off_default_no_elicitation", func(t *testing.T) {
		keeper := &fakeKeeper{}
		session, rec := newConfirmBridge(t, ctx, keeper, nil, nil, revisionLegacy)
		result := callTool(t, ctx, session, "remote_upload", callOptions{overwrite: true})
		if result.IsError || result.RequestState != "" || len(result.InputRequests) != 0 {
			t.Fatalf("a legacy client was elicited with the feature off: %+v", result)
		}
		startedUpload(t, result, keeper)
		for _, needle := range []string{"inputRequests", "input_required", "elicitation"} {
			if last := rec.last(); last != nil && strings.Contains(string(last), needle) {
				t.Fatalf("the wire answer contains %s: %s", needle, last)
			}
		}
		if ops := keeper.recorded(); len(ops) != 1 || ops[0] != "transfer_upload" {
			t.Fatalf("the keeper saw %v, want one transfer_upload", ops)
		}
	})
	t.Run("off_default_modern_form_meta", func(t *testing.T) {
		keeper := &fakeKeeper{}
		session, rec := newConfirmBridge(t, ctx, keeper, nil, nil, revision2026)
		result := callTool(t, ctx, session, "remote_upload", callOptions{meta: formMeta(), overwrite: true})
		if result.IsError || result.RequestState != "" || len(result.InputRequests) != 0 {
			t.Fatalf("a modern form client was elicited with the feature off: %+v", result)
		}
		startedUpload(t, result, keeper)
		if last := rec.last(); last != nil && strings.Contains(string(last), "input_required") {
			t.Fatalf("the wire answer carries input_required: %s", last)
		}
	})
}

func TestConfirmGateEligibility(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	newManager := func(now func() time.Time) *confirm.Manager { return confirm.NewManager(now, nil) }
	t.Run("on_without_meta_form_passthrough", func(t *testing.T) {
		keeper := &fakeKeeper{}
		session, _ := newConfirmBridge(t, ctx, keeper, nil, newManager(nil), revision2026)
		result := callTool(t, ctx, session, "remote_upload", callOptions{overwrite: true})
		if result.RequestState != "" || len(result.InputRequests) != 0 {
			t.Fatalf("a call without form meta was elicited: %+v", result)
		}
		startedUpload(t, result, keeper)
	})
	t.Run("on_url_only_meta_passthrough", func(t *testing.T) {
		keeper := &fakeKeeper{}
		session, _ := newConfirmBridge(t, ctx, keeper, nil, newManager(nil), revision2026)
		result := callTool(t, ctx, session, "remote_upload", callOptions{meta: urlOnlyMeta(), overwrite: true})
		if result.RequestState != "" || len(result.InputRequests) != 0 {
			t.Fatalf("a URL-only client was elicited: %+v", result)
		}
		startedUpload(t, result, keeper)
	})
	t.Run("on_null_form_meta_passthrough", func(t *testing.T) {
		keeper := &fakeKeeper{}
		session, rec := newConfirmBridge(t, ctx, keeper, nil, newManager(nil), revision2026)
		result := callTool(t, ctx, session, "remote_upload", callOptions{meta: nullFormMeta(), overwrite: true})
		if result.RequestState != "" || len(result.InputRequests) != 0 {
			t.Fatalf("a null-form client was elicited: %+v", result)
		}
		startedUpload(t, result, keeper)
		if last := rec.last(); last != nil && strings.Contains(string(last), "input_required") {
			t.Fatalf("the raw wire answer carries input_required: %s", last)
		}
	})
	t.Run("on_without_overwrite_passthrough", func(t *testing.T) {
		keeper := &fakeKeeper{}
		session, _ := newConfirmBridge(t, ctx, keeper, nil, newManager(nil), revision2026)
		result := callTool(t, ctx, session, "remote_upload", callOptions{meta: formMeta()})
		if result.RequestState != "" || len(result.InputRequests) != 0 {
			t.Fatalf("an overwrite=false call was elicited: %+v", result)
		}
		startedUpload(t, result, keeper)
	})
	// Note: a "modern session, meta WITHOUT protocolVersion" case is NOT
	// achievable at SDK level: the SDK client always injects
	// io.modelcontextprotocol/protocolVersion into the request `_meta`
	// (client.go:540-541, usesNewProtocol only gates the VALUE, not the
	// presence). That case is covered by the raw harness (rawwire_test.go).
	t.Run("on_legacy_request_meta_form_version_never_elicits", func(t *testing.T) {
		keeper := &fakeKeeper{}
		session, _ := newConfirmBridge(t, ctx, keeper, nil, newManager(nil), revisionLegacy)
		result := callTool(t, ctx, session, "remote_upload", callOptions{meta: formMeta(), overwrite: true})
		// The deciding factor is the per-request meta: on a legacy session the
		// client injects NO modern protocolVersion (usesNewProtocol is false),
		// so the request carries a form capability but no 2026-07-28 version
		// meta and is INELIGIBLE under the exact-match gate.
		if result.RequestState != "" || len(result.InputRequests) != 0 {
			t.Fatalf("a legacy request without version meta was elicited: %+v", result)
		}
		startedUpload(t, result, keeper)
	})
	t.Run("app_exec_no_elicitation_without_classification", func(t *testing.T) {
		keeper := &fakeKeeper{}
		session, _ := newConfirmBridge(t, ctx, keeper, nil, newManager(nil), revision2026)
		result := callTool(t, ctx, session, "app_exec", callOptions{meta: formMeta()})
		if result.RequestState != "" || len(result.InputRequests) != 0 || result.IsError {
			t.Fatalf("app_exec was elicited without a classifier: %+v", result)
		}
		if text := answerText(t, result); !strings.HasPrefix(text, "Started job ") {
			t.Fatalf("app_exec answered %q", text)
		}
		if ops := keeper.recorded(); len(ops) != 1 || ops[0] != "app_start" {
			t.Fatalf("the keeper saw %v, want one app_start", ops)
		}
	})
}
