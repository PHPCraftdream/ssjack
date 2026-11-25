package remotemcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
	"github.com/PHPCraftdream/ssjack/internal/lifelog"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunMCPBootstrapProtocolDiscoverKeepsKeeperAttachment(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"ssjack":{"type":"stdio","command":"ssjack","args":["mcp"]}}}`), 0600); err != nil {
		t.Fatal("could not create fixed MCP config")
	}
	t.Chdir(root)

	session, token := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var countsMu sync.Mutex
	counts := make(map[string]int)
	attachedEvents := 0
	keeper, err := broker.ListenTraced(context.Background(), session, token, time.Minute, func(_ context.Context, request wire.Request) wire.Reply {
		countsMu.Lock()
		counts[request.Operation]++
		countsMu.Unlock()
		switch request.Operation {
		case "session.describe":
			return broker.Result(broker.Descriptor{
				Protocol: broker.FullProtocol, Mode: broker.ModeFull, Complete: true,
				Tools: []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel", "remote_upload", "remote_download", "transfer_status", "transfer_cancel"},
			}, nil)
		case "targets":
			return broker.Result(remote.TargetsOutput{Targets: []string{"synthetic-target"}}, nil)
		default:
			return wire.Reply{Error: "unexpected operation"}
		}
	}, func(event string, _ ...string) {
		if event == "attached" {
			countsMu.Lock()
			attachedEvents++
			countsMu.Unlock()
		}
	})
	if err != nil {
		t.Fatal("local synthetic keeper unavailable")
	}
	defer keeper.Close()

	lifecyclePath := filepath.Join(root, ".claude", "ssjack", "lifecycle.log")
	for key, value := range map[string]string{
		broker.EnvSession: session, broker.EnvToken: token, broker.EnvEndpoint: keeper.Endpoint(), broker.EnvPin: keeper.Pin(),
		broker.EnvFile: "synthetic-stale-bootstrap-file", "SSJACK_APP_ENDPOINT": "synthetic-stale-app-endpoint",
		"SSJACK_APP_TOKEN": "synthetic-stale-app-token", "SSJACK_APP_CERTIFICATE_SHA256": "synthetic-stale-app-pin",
	} {
		t.Setenv(key, value)
	}
	t.Setenv(mcpchannel.Env, "")
	if err := os.Unsetenv(mcpchannel.Env); err != nil {
		t.Fatal("could not clear channel descriptors")
	}
	t.Setenv(lifelog.Env, lifecyclePath)

	serverIn, clientIn, err := os.Pipe()
	if err != nil {
		t.Fatal("could not create MCP input pipe")
	}
	clientOut, serverOut, err := os.Pipe()
	if err != nil {
		serverIn.Close()
		clientIn.Close()
		t.Fatal("could not create MCP output pipe")
	}
	previousIn, previousOut := os.Stdin, os.Stdout
	stdinReplaced, stdoutReplaced := true, true
	os.Stdin, os.Stdout = serverIn, serverOut
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	type runResult struct {
		code int
		err  error
	}
	resultCh, runDone := make(chan runResult, 1), make(chan struct{})
	go func() {
		code, runErr := runMCP(ctx)
		resultCh <- runResult{code: code, err: runErr}
		close(runDone)
	}()
	joined := false
	cleanup := func() {
		_ = clientIn.Close() // EOF is the normal stdio shutdown signal.
		if !joined {
			select {
			case <-runDone:
				joined = true
			case <-time.After(3 * time.Second):
				cancel()
				_ = serverIn.Close()
				_ = clientOut.Close()
				_ = serverOut.Close()
				select {
				case <-runDone:
					joined = true
				case <-time.After(3 * time.Second):
					t.Error("runMCP goroutine did not join")
				}
			}
		}
		if joined {
			if stdinReplaced {
				os.Stdin = previousIn
				stdinReplaced = false
			}
			if stdoutReplaced {
				os.Stdout = previousOut
				stdoutReplaced = false
			}
		}
		cancel()
		if joined {
			_ = serverIn.Close()
			_ = serverOut.Close()
			_ = clientOut.Close()
		}
	}
	defer cleanup()

	// ConnectBootstrap spends this one-use token before discovery. The broker closes
	// its listener on the first attachment, so repeat discovery must keep using
	// the live attachment; it cannot spend the token again or reattach.
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"synthetic-bootstrap-client","version":"synthetic-client-version"}}`
	writeMCPFrame(t, clientIn, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+meta+`}}`)
	firstDiscover := sdkCallResults(t, readMCPLine(t, clientOut), false, 1)[1]
	assertBootstrapProtocolDiscover(t, firstDiscover)
	select {
	case <-keeper.Attached():
	default:
		t.Fatal("bootstrap did not attach before discovery")
	}
	assertBootstrapKeeperCounts(t, &countsMu, counts, &attachedEvents, 1, 0, 1)

	writeMCPFrame(t, clientIn, `{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{`+meta+`}}`)
	secondDiscover := sdkCallResults(t, readMCPLine(t, clientOut), false, 2)[2]
	assertBootstrapProtocolDiscover(t, secondDiscover)
	assertBootstrapKeeperCounts(t, &countsMu, counts, &attachedEvents, 1, 0, 1)
	select {
	case <-keeper.Attached():
	default:
		t.Fatal("repeat discovery lost the keeper attachment")
	}

	writeMCPFrame(t, clientIn, `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{`+meta+`}}`)
	listed := sdkCallResults(t, readMCPLine(t, clientOut), false, 3)[3]
	tools, ok := listed["tools"].([]any)
	wantTools := []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel", "remote_upload", "remote_download", "transfer_status", "transfer_cancel"}
	if !ok || len(tools) != len(wantTools) {
		t.Fatal("tools/list did not return the full descriptor")
	}
	toolNames := make(map[string]bool, len(tools))
	for _, entry := range tools {
		tool, ok := entry.(map[string]any)
		if !ok {
			t.Fatal("tools/list returned an invalid tool entry")
		}
		name, ok := tool["name"].(string)
		if !ok {
			t.Fatal("tools/list returned an unnamed tool")
		}
		toolNames[name] = true
	}
	for _, want := range wantTools {
		if !toolNames[want] {
			t.Fatal("tools/list omitted a descriptor tool")
		}
	}

	writeMCPFrame(t, clientIn, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"remote_targets","arguments":{},`+meta+`}}`)
	called := sdkCallResults(t, readMCPLine(t, clientOut), false, 4)[4]
	content, ok := called["content"].([]any)
	var text string
	if ok && len(content) == 1 {
		block, _ := content[0].(map[string]any)
		text, _ = block["text"].(string)
	}
	if _, structured := called["structuredContent"]; structured || called["isError"] == true || !ok || len(content) != 1 || text != "1 approved target:\n- synthetic-target" {
		t.Fatal("remote_targets did not return the attached keeper result")
	}
	assertBootstrapKeeperCounts(t, &countsMu, counts, &attachedEvents, 1, 1, 1)

	if err := clientIn.Close(); err != nil {
		t.Fatal("could not send clean stdio EOF")
	}
	var run runResult
	select {
	case run = <-resultCh:
	case <-time.After(3 * time.Second):
		t.Fatal("runMCP did not finish after clean EOF")
	}
	select {
	case <-runDone:
		joined = true
	case <-time.After(time.Second):
		t.Fatal("runMCP completion was not joined")
	}
	if run.code != 0 || run.err != nil {
		t.Fatal("runMCP did not complete successfully")
	}
	cleanup()
	keeper.Close()

	for _, key := range []string{broker.EnvFile, broker.EnvSession, broker.EnvToken, broker.EnvEndpoint, broker.EnvPin, mcpchannel.Env,
		"SSJACK_APP_ENDPOINT", "SSJACK_APP_TOKEN", "SSJACK_APP_CERTIFICATE_SHA256"} {
		if _, exists := os.LookupEnv(key); exists {
			t.Fatalf("reserved bootstrap environment survived: %s", key)
		}
	}

	log, err := os.ReadFile(lifecyclePath)
	if err != nil {
		t.Fatal("lifecycle log was not written")
	}
	shape := regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z pid=\d+ role=mcp sid=[0-9a-f]{8} event=[A-Za-z0-9_.:-]+( [A-Za-z0-9_.:-]+=[A-Za-z0-9_.:-]+)*$`)
	lines := strings.Split(strings.TrimSuffix(string(log), "\n"), "\n")
	seenEvents := make(map[string]bool)
	for _, line := range lines {
		if !shape.MatchString(line) {
			t.Fatal("lifecycle log left its closed alphabet")
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "event=") {
				seenEvents[strings.TrimPrefix(field, "event=")] = true
			}
		}
	}
	for _, event := range []string{"attached", "serving", "stdio-end", "exit"} {
		if !seenEvents[event] {
			t.Fatal("lifecycle log omitted a required event")
		}
	}
	for _, private := range []string{
		session, token, keeper.Endpoint(), keeper.Pin(), "synthetic-bootstrap-client", "synthetic-client-version", "synthetic-target",
		"synthetic-stale-bootstrap-file", "synthetic-stale-app-endpoint", "synthetic-stale-app-token", "synthetic-stale-app-pin",
		"server/discover", "tools/list", "tools/call", "remote_targets",
	} {
		if strings.Contains(string(log), private) {
			t.Fatal("lifecycle log exposed bootstrap or request data")
		}
	}
}

func assertBootstrapProtocolDiscover(t *testing.T, result map[string]any) {
	t.Helper()
	versions, ok := result["supportedVersions"].([]any)
	want := []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
	if !ok || len(versions) != len(want) {
		t.Fatal("server/discover returned an unexpected protocol version list")
	}
	for i, version := range want {
		if versions[i] != version {
			t.Fatal("server/discover protocol versions were not newest first")
		}
	}
	capabilities, ok := result["capabilities"].(map[string]any)
	tools, toolsOK := capabilities["tools"].(map[string]any)
	if !ok || !toolsOK || tools["listChanged"] != true {
		t.Fatal("server/discover omitted tool capabilities")
	}
	meta, ok := result["_meta"].(map[string]any)
	identity, identityOK := meta["io.modelcontextprotocol/serverInfo"].(map[string]any)
	if !ok || !identityOK || identity["name"] != "ssjack" || identity["version"] != buildinfo.Version {
		t.Fatal("server/discover omitted ssjack identity")
	}
}

func assertBootstrapKeeperCounts(t *testing.T, mu *sync.Mutex, counts map[string]int, attachedEvents *int, describes, targets, confirms int) {
	t.Helper()
	mu.Lock()
	wantOperations := 0
	if describes != 0 {
		wantOperations++
	}
	if targets != 0 {
		wantOperations++
	}
	if confirms != 0 {
		wantOperations++
	}
	if counts["session.describe"] != describes || counts["targets"] != targets || counts["confirm_config"] != confirms || len(counts) != wantOperations || *attachedEvents != 1 {
		mu.Unlock()
		t.Fatal("discovery caused an unexpected keeper operation")
	}
	mu.Unlock()
}

func TestMCPStdioRejectsModernBatchesBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame string
	}{
		{
			name:  "latest modern metadata without initialize",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}]`,
		},
		{
			name:  "mixed legacy and latest modern metadata",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26"}}},{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}]`,
		},
		{
			name:  "modern metadata without initialize",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}}]`,
		},
		{
			name:  "mixed legacy and modern metadata",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26"}}},{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}}]`,
		},
		{
			name:  "newer initialize offer",
			frame: `[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}},{"jsonrpc":"2.0","id":2,"method":"ping"}]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := bytes.NewBuffer(nil)
			connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(tc.frame+"\n")), nopWriteCloser{out})
			if _, err := connection.Read(context.Background()); !errors.Is(err, errMCPStdioBatchUnsupported) {
				t.Fatalf("modern batch error = %v, want errMCPStdioBatchUnsupported", err)
			}
			if out.Len() != 0 {
				t.Fatalf("refused modern batch wrote to stdout: %q", out.String())
			}
			if connection.protocolVersion != "" {
				t.Fatalf("refused batch changed the legacy protocol tracker: %q", connection.protocolVersion)
			}
		})
	}
}

func TestMCPStdioRejectsMalformedBatchesBeforeTracking(t *testing.T) {
	cases := []struct {
		name   string
		method string
		params string
	}{
		{
			name:   "wrong typed top-level version with modern metadata",
			method: "tools/list",
			params: `{"protocolVersion":false,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`,
		},
		{name: "metadata array", method: "ping", params: `{"_meta":[]}`},
		{name: "metadata string", method: "ping", params: `{"_meta":"bad"}`},
		{name: "metadata boolean", method: "ping", params: `{"_meta":true}`},
		{name: "metadata null", method: "ping", params: `{"_meta":null}`},
		{name: "params array", method: "ping", params: `[]`},
		{name: "params boolean", method: "ping", params: `false`},
		{name: "params null", method: "ping", params: `null`},
		{name: "params string", method: "ping", params: `"bad"`},
		{name: "modern initialize offer", method: "initialize", params: `{"protocolVersion":"2026-07-28"}`},
		{name: "future initialize offer", method: "initialize", params: `{"protocolVersion":"2099-01-01"}`},
		{name: "initialize at modern cutoff", method: "initialize", params: `{"protocolVersion":"2025-06-18"}`},
	}
	for _, value := range []string{"", "nonsense", "2025-99-99", "2025-03-26T00:00:00Z"} {
		cases = append(cases,
			struct {
				name   string
				method string
				params string
			}{name: "malformed top-level date " + value, method: "tools/list", params: `{"protocolVersion":` + mustJSONTestString(t, value) + `}`},
			struct {
				name   string
				method string
				params string
			}{name: "malformed metadata date " + value, method: "ping", params: `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + mustJSONTestString(t, value) + `}}`},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := `[ {"jsonrpc":"2.0","id":1,"method":` + mustJSONTestString(t, tc.method) + `,"params":` + tc.params + `} ]` + "\n"
			out := bytes.NewBuffer(nil)
			connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(frame)), nopWriteCloser{out})
			if _, err := connection.Read(context.Background()); !errors.Is(err, errMCPStdioBatchUnsupported) {
				t.Fatalf("malformed batch error = %v, want errMCPStdioBatchUnsupported", err)
			}
			if out.Len() != 0 {
				t.Fatalf("refused malformed batch wrote to stdout: %q", out.String())
			}
			if connection.protocolVersion != "" || len(connection.batches) != 0 {
				t.Fatalf("refused malformed batch changed legacy tracking: version=%q batches=%d", connection.protocolVersion, len(connection.batches))
			}
		})
	}
}

func TestBatchHasModernProtocolVersionRejectsMalformedRawParams(t *testing.T) {
	request := &jsonrpc.Request{Method: "ping", Params: json.RawMessage(`{"malformed":`)}
	if !batchHasModernProtocolVersion([]jsonrpc.Message{request}) {
		t.Fatal("malformed raw params were not conservatively rejected")
	}
}

func TestMCPStdioKeepsLegacyBatchesSupported(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		params string
	}{
		{name: "legacy ping without params", method: "ping"},
		{name: "earliest initialize", method: "initialize", params: `{"protocolVersion":"2024-11-05"}`},
		{name: "next initialize", method: "initialize", params: `{"protocolVersion":"2025-03-26"}`},
		{name: "legacy metadata", method: "ping", params: `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := ""
			if tc.params != "" {
				params = `,"params":` + tc.params
			}
			frame := `[ {"jsonrpc":"2.0","id":1,"method":` + mustJSONTestString(t, tc.method) + params + `} ]` + "\n"
			connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(frame)), nopWriteCloser{bytes.NewBuffer(nil)})
			if _, err := connection.Read(context.Background()); err != nil {
				t.Fatalf("legacy batch was refused: %v", err)
			}
			if len(connection.batches) != 1 {
				t.Fatalf("legacy batch tracked %d IDs, want 1", len(connection.batches))
			}
		})
	}
}

func mustJSONTestString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestMCPStdioModernRequestDoesNotChangeLegacyBatchTracking(t *testing.T) {
	modern := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	var stream strings.Builder
	stream.WriteString(modern + "\n")
	for i, version := range []string{mcpProtocol20241105, mcpProtocol20250326} {
		firstID, secondID := 10+int64(i)*10, 11+int64(i)*10
		fmt.Fprintf(&stream,
			`[{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}},{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}}]`+"\n",
			firstID, version, secondID, version)
	}

	out := bytes.NewBuffer(nil)
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream.String())), nopWriteCloser{out})
	readMCPCall := func(wantID int64) {
		t.Helper()
		message, err := connection.Read(context.Background())
		if err != nil {
			t.Fatalf("read call %d: %v", wantID, err)
		}
		request, ok := message.(*jsonrpc.Request)
		if !ok || request.Method != "ping" || request.ID.Raw() != wantID {
			t.Fatalf("read call = %#v, want ping id %d", message, wantID)
		}
	}

	readMCPCall(1)
	if connection.protocolVersion != "" {
		t.Fatalf("modern per-request metadata changed the legacy tracker: %q", connection.protocolVersion)
	}
	for i, version := range []string{mcpProtocol20241105, mcpProtocol20250326} {
		firstID, secondID := 10+int64(i)*10, 11+int64(i)*10
		readMCPCall(firstID)
		readMCPCall(secondID)
		if connection.protocolVersion != "" {
			t.Fatalf("legacy batch %s changed the initialize tracker: %q", version, connection.protocolVersion)
		}
		for _, id := range []int64{firstID, secondID} {
			jsonID, err := jsonrpc.MakeID(float64(id))
			if err != nil {
				t.Fatal(err)
			}
			if err := connection.Write(context.Background(), &jsonrpc.Response{ID: jsonID, Result: json.RawMessage(`{"ok":true}`)}); err != nil {
				t.Fatalf("write batch response %d: %v", id, err)
			}
		}
		var responses []struct {
			ID     int64           `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &responses); err != nil {
			t.Fatalf("legacy %s batch response was not an array: %q (%v)", version, out.String(), err)
		}
		if len(responses) != 2 || responses[0].ID != firstID || responses[1].ID != secondID || len(responses[0].Result) == 0 || len(responses[1].Result) == 0 || len(responses[0].Error) != 0 || len(responses[1].Error) != 0 {
			t.Fatalf("legacy %s batch responses were not aggregated in request order: %#v", version, responses)
		}
		out.Reset()
	}
}

func TestMCPStdioModernMetadataKeepsFrameDepthAndDuplicateBounds(t *testing.T) {
	const modernMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
	base := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + modernMeta + `}}`)
	for _, size := range []int{maxMCPStdioMessage, maxMCPStdioMessage + 1} {
		frame := append(append([]byte(nil), base...), bytes.Repeat([]byte{' '}, size-len(base))...)
		input := &fragmentedMCPInput{data: frame, n: 137}
		connection := newMCPStdioTransport(input, nopWriteCloser{bytes.NewBuffer(nil)})
		message, err := connection.Read(context.Background())
		if size == maxMCPStdioMessage {
			request, ok := message.(*jsonrpc.Request)
			if err != nil || !ok || request.Method != "ping" {
				t.Fatalf("fragmented modern-metadata frame at exact byte bound was refused: %#v, %v", message, err)
			}
		} else if !errors.Is(err, errMCPStdioMessageLimit) {
			t.Fatalf("fragmented modern-metadata frame over byte bound error = %v", err)
		}
	}

	deep := `{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"nested":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}}` + "\n"
	deepReader := newBoundedMCPStdioReader(&fragmentedMCPInput{data: []byte(deep), n: 11})
	if n, err := deepReader.Read(make([]byte, maxMCPStdioMessage+1)); n != 0 || !errors.Is(err, errMCPStdioInvalidMessage) {
		t.Fatalf("over-depth modern metadata frame yielded %d bytes with error %v", n, err)
	}

	duplicate := `{"jsonrpc":"2.0","id":3,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2024-11-05","io.modelcontextprotocol/protocolVersion":"2025-03-26"}}}` + "\n"
	duplicateReader := newBoundedMCPStdioReader(&fragmentedMCPInput{data: []byte(duplicate), n: 7})
	if n, err := duplicateReader.Read(make([]byte, maxMCPStdioMessage+1)); n != 0 || !errors.Is(err, errMCPStdioInvalidMessage) {
		t.Fatalf("duplicate modern metadata version yielded %d bytes with error %v", n, err)
	}
}

func TestMCPStdioUnsupportedMetaRefusalsSpendMessageBound(t *testing.T) {
	var stream strings.Builder
	for id := 1; id <= maxMCPStdioMessages; id++ {
		fmt.Fprintf(&stream, `{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}}`+"\n", id)
	}
	stream.WriteString(`{"jsonrpc":"2.0","id":5000,"method":"ping"}` + "\n")
	out := bytes.NewBuffer(nil)
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream.String())), nopWriteCloser{out})
	if _, err := connection.Read(context.Background()); !errors.Is(err, errMCPStdioMessageCountLimit) {
		t.Fatalf("message after %d unsupported-version refusals returned %v", maxMCPStdioMessages, err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != maxMCPStdioMessages {
		t.Fatalf("got %d unsupported-version responses, want %d", len(lines), maxMCPStdioMessages)
	}
	for i, line := range lines {
		var response struct {
			ID    int64 `json:"id"`
			Error struct {
				Code int64 `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &response); err != nil || response.ID != int64(i+1) || response.Error.Code != -32022 {
			t.Fatalf("unsupported-version response %d was not the raw -32022 refusal: %q (%v)", i+1, line, err)
		}
	}

	wrapped := fmt.Errorf("batch unsupported in 2099-01-01 and later: %w", errMCPStdioBatchUnsupported)
	if cause := stdioCause(wrapped); cause != "unsupported-batch" || strings.Contains(cause, "2099-01-01") {
		t.Fatalf("stdioCause leaked an arbitrary protocol version: %q", cause)
	}
}

// sdkCallResults decodes one reply line with the pinned SDK decoder, asserts
// the wire container and each response envelope (exact ids, no error field,
// object result), and returns the result objects keyed by numeric id.
func sdkCallResults(t *testing.T, line string, wantArray bool, wantIDs ...int64) map[int64]map[string]any {
	t.Helper()
	trimmed := bytes.TrimSpace([]byte(strings.TrimSuffix(line, "\n")))
	if len(trimmed) == 0 || (trimmed[0] == '[') != wantArray {
		t.Fatalf("reply container mismatch: want array=%v got %s", wantArray, trimmed)
	}
	var raws []json.RawMessage
	if wantArray {
		if err := json.Unmarshal(trimmed, &raws); err != nil {
			t.Fatalf("array reply line did not decode: %s", trimmed)
		}
	} else {
		raws = []json.RawMessage{trimmed}
	}
	if len(raws) != len(wantIDs) {
		t.Fatalf("reply carried %d responses, want %d: %s", len(raws), len(wantIDs), trimmed)
	}
	results := make(map[int64]map[string]any, len(wantIDs))
	for _, raw := range raws {
		message, err := jsonrpc.DecodeMessage(raw)
		if err != nil {
			t.Fatalf("reply message did not decode: %v", err)
		}
		response, ok := message.(*jsonrpc.Response)
		if !ok {
			t.Fatalf("reply carried a non-response message: %#v", message)
		}
		gotID, ok := response.ID.Raw().(int64)
		if !ok {
			t.Fatalf("response id %v is %T, want an int64", response.ID.Raw(), response.ID.Raw())
		}
		if _, dup := results[gotID]; dup {
			t.Fatalf("reply carried duplicate id %v", gotID)
		}
		var envelope struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("response envelope did not decode: %v", err)
		}
		if len(envelope.Error) != 0 {
			t.Fatalf("response for id %v carried an error field: %s", gotID, envelope.Error)
		}
		var result map[string]any
		if err := json.Unmarshal(envelope.Result, &result); err != nil {
			t.Fatalf("result for id %v was not a JSON object: %s", gotID, envelope.Result)
		}
		if result == nil {
			t.Fatalf("result for id %v was JSON null, want an object", gotID)
		}
		results[gotID] = result
	}
	for _, want := range wantIDs {
		if _, ok := results[want]; !ok {
			t.Fatalf("reply lost the response for id %d: %#v", want, results)
		}
	}
	return results
}

// joinExited bounded-asserts one worker exit; cleanup-safe because it uses
// t.Error instead of t.Fatal, so every joined worker is reported.
func joinExited(t *testing.T, exited <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Error(message)
	}
}

func writeMCPFrame(t *testing.T, w io.WriteCloser, frame string) {
	t.Helper()
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		_, err := io.WriteString(w, frame+"\n")
		done <- err
	}()
	select {
	case err := <-done:
		awaitSignal(t, exited, "frame write worker did not exit")
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		w.Close()
		awaitSignal(t, exited, "frame write worker did not exit after its writer was released")
		t.Fatal("bounded frame write blocked")
	}
	awaitSignal(t, exited, "frame write worker did not exit")
}

// readMCPLine reads one newline-terminated line byte-by-byte without
// prefetching, so no bytes beyond the line are consumed from r.
func readMCPLine(t *testing.T, r io.ReadCloser) string {
	t.Helper()
	done := make(chan string, 1)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		var line []byte
		one := make([]byte, 1)
		for {
			n, err := r.Read(one)
			line = append(line, one[:n]...)
			if n > 0 && line[len(line)-1] == '\n' {
				done <- string(line)
				return
			}
			if err != nil {
				done <- string(line)
				return
			}
		}
	}()
	select {
	case text := <-done:
		awaitSignal(t, exited, "reply read worker did not exit")
		return text
	case <-time.After(2 * time.Second):
		r.Close()
		awaitSignal(t, exited, "reply read worker did not exit after its reader was released")
		t.Fatal("owned reply line did not arrive")
	}
	return ""
}

// awaitSignal joins one owned worker or gate with the shared one-second budget.
func awaitSignal[T any](t *testing.T, signal <-chan T, message string) T {
	t.Helper()
	select {
	case value := <-signal:
		return value
	case <-time.After(time.Second):
		t.Fatal(message)
	}
	var zero T
	return zero
}

// startStdioSDKFixture runs the real pinned SDK server over owned pipes and
// registers a cleanup that cancels orderly, releases every pipe endpoint, and
// joins the server goroutine bounded.
func startStdioSDKFixture(t *testing.T, name string) (io.WriteCloser, io.ReadCloser, context.CancelFunc, <-chan error) {
	serverIn, serverInWriter := io.Pipe()
	clientOut, clientOutWriter := io.Pipe()
	server := mcp.NewServer(&mcp.Implementation{Name: name, Version: "1"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	configureMCPStdioServer(server, ctx)
	runErr, runDone := make(chan error, 1), make(chan struct{})
	go func() { runErr <- server.Run(ctx, newMCPStdioTransport(serverIn, clientOutWriter)); close(runDone) }()
	t.Cleanup(func() {
		cancel()
		clientOutWriter.Close()
		clientOut.Close()
		serverInWriter.Close()
		select {
		case <-runDone:
		case <-time.After(time.Second):
			t.Error("owned server goroutine did not join")
		}
	})
	return serverInWriter, clientOut, cancel, runErr
}

func TestMCPStdioNegotiationRefusesBatchAfter20250618(t *testing.T) {
	in, out, _, runErr := startStdioSDKFixture(t, "stdio-negotiation-fixture")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	line := readMCPLine(t, out)
	if !strings.Contains(line, `"id":1`) || !strings.Contains(line, `"protocolVersion":"`+mcpProtocol20250618+`"`) {
		t.Fatalf("initialize response lost the negotiated version: %q", line)
	}
	writeMCPFrame(t, in, `[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`)
	select {
	case err := <-runErr:
		if err == nil || !strings.Contains(err.Error(), "batching") {
			t.Fatalf("post-2025-06-18 batch was not refused by the negotiated version: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("negotiated batch refusal did not terminate the SDK server run")
	}
}

func TestMCPStdioSDKAnswersLegacyBatchWithSingleArray(t *testing.T) {
	in, out, cancel, runErr := startStdioSDKFixture(t, "stdio-batch-fixture")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	line := readMCPLine(t, out)
	if !strings.Contains(line, `"id":1`) || !strings.Contains(line, `"protocolVersion":"2024-11-05"`) {
		t.Fatalf("initialize response lost its negotiated legacy version: %q", line)
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	writeMCPFrame(t, in, `[{"jsonrpc":"2.0","id":2,"method":"ping"},{"jsonrpc":"2.0","id":3,"method":"tools/list"}]`)
	results := sdkCallResults(t, readMCPLine(t, out), true, 2, 3)
	if len(results[2]) != 0 {
		t.Fatalf("ping result was not the empty object: %#v", results[2])
	}
	tools, ok := results[3]["tools"].([]any)
	if !ok || len(tools) != 0 {
		t.Fatalf("tools/list result did not carry an empty tools array: %#v", results[3]["tools"])
	}
	cancel()
	if err := awaitSignal(t, runErr, "owned server run did not join"); !errors.Is(err, context.Canceled) {
		t.Fatalf("owned server run did not end with the orderly cancellation: %v", err)
	}
}

func TestMCPStdioSDKMixedBatchEmitsCallResponseOnly(t *testing.T) {
	in, out, cancel, runErr := startStdioSDKFixture(t, "stdio-mixed-fixture")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	line := readMCPLine(t, out)
	if !strings.Contains(line, `"id":1`) || !strings.Contains(line, `"protocolVersion":"2024-11-05"`) {
		t.Fatalf("initialize response lost its negotiated legacy version: %q", line)
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	writeMCPFrame(t, in, `[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`)
	results := sdkCallResults(t, readMCPLine(t, out), true, 2)
	if len(results[2]) != 0 {
		t.Fatalf("mixed legacy batch ping result was not the empty object: %#v", results[2])
	}
	cancel()
	if err := awaitSignal(t, runErr, "owned server run did not join"); !errors.Is(err, context.Canceled) {
		t.Fatalf("owned server run did not end with the orderly cancellation: %v", err)
	}
}

func TestMCPStdioSDKNotificationOnlyBatchEmitsNoReply(t *testing.T) {
	in, out, cancel, runErr := startStdioSDKFixture(t, "stdio-quiet-fixture")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	line := readMCPLine(t, out)
	if !strings.Contains(line, `"id":1`) || !strings.Contains(line, `"protocolVersion":"2024-11-05"`) {
		t.Fatalf("initialize response lost its negotiated legacy version: %q", line)
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	writeMCPFrame(t, in, `[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","method":"ping"}]`)
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":4,"method":"ping"}`)
	results := sdkCallResults(t, readMCPLine(t, out), false, 4)
	if len(results[4]) != 0 {
		t.Fatalf("id 4 ping result was not the empty object: %#v", results[4])
	}
	cancel()
	if err := awaitSignal(t, runErr, "owned server run did not join"); !errors.Is(err, context.Canceled) {
		t.Fatalf("owned server run did not end with the orderly cancellation: %v", err)
	}
}

func TestMCPStdioConnectionBuffersIncompleteBatchUnderClose(t *testing.T) {
	stream := []byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]` + "\n")
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(stream)), &scriptedWriter{})
	if _, err := connection.Read(context.Background()); err != nil {
		t.Fatalf("two-call legacy batch head did not decode: %v", err)
	}
	firstResponse, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	if err != nil {
		t.Fatalf("first tracked response did not decode: %v", err)
	}
	if err := connection.Write(context.Background(), firstResponse); err != nil {
		t.Fatalf("incomplete tracked response was not buffered: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("owned close failed: %v", err)
	}
	secondResponse, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`))
	if err != nil {
		t.Fatalf("second tracked response did not decode: %v", err)
	}
	if err := connection.Write(context.Background(), secondResponse); !errors.Is(err, errMCPStdioWriterClosed) {
		t.Fatalf("tracked response after close lost the fixed refusal: %v", err)
	}
	connection.batchMu.Lock()
	tracked := len(connection.batches)
	connection.batchMu.Unlock()
	if tracked != 1 {
		t.Fatalf("incomplete buffered batch was dropped after close: %d entries", tracked)
	}
}

func TestResolveConfirmManagerUsesKeeperConfiguration(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		got, _, _, _, _ := resolveConfirmManagerScenario(t, true, false)
		if got == nil {
			t.Fatal("manager is nil for enabled configuration")
		}
	})
	t.Run("disabled", func(t *testing.T) {
		got, operations, ctx, client, cancel := resolveConfirmManagerScenario(t, false, false)
		defer cancel()
		if got != nil {
			t.Fatal("manager is present for disabled configuration")
		}
		assertConfirmOffDispatch(t, ctx, client, operations)
	})
	t.Run("unavailable", func(t *testing.T) {
		got, operations, ctx, client, cancel := resolveConfirmManagerScenario(t, false, true)
		defer cancel()
		if got != nil {
			t.Fatal("manager is present for unavailable configuration")
		}
		assertConfirmOffDispatch(t, ctx, client, operations)
	})
}

func resolveConfirmManagerScenario(t *testing.T, enabled, callError bool) (*bridge.ConfirmManager, func() []string, context.Context, *broker.Client, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	session, token := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var operationsMu sync.Mutex
	var operations []string
	keeper, err := broker.Listen(ctx, session, token, time.Minute, func(_ context.Context, request wire.Request) wire.Reply {
		operationsMu.Lock()
		operations = append(operations, request.Operation)
		operationsMu.Unlock()
		switch request.Operation {
		case "confirm_config":
			if callError {
				return wire.Reply{Error: "configuration unavailable"}
			}
			return broker.Result(map[string]bool{"confirm_elicitation": enabled}, nil)
		case "transfer_upload":
			return broker.Result(remote.StartOutput{JobID: strings.Repeat("a", 64)}, nil)
		default:
			return wire.Reply{Error: "unexpected operation"}
		}
	})
	if err != nil {
		cancel()
		t.Fatal("could not start synthetic keeper")
	}
	t.Cleanup(keeper.Close)
	client, err := broker.Connect(ctx, keeper.Endpoint(), keeper.Pin(), wire.Auth{Version: 2, Session: session, Token: token})
	if err != nil {
		cancel()
		t.Fatal("could not connect synthetic keeper")
	}
	t.Cleanup(func() { client.Close() })
	got := resolveConfirmManager(ctx, client, broker.Descriptor{Mode: broker.ModeFull}, nil)
	operationSnapshot := func() []string {
		operationsMu.Lock()
		defer operationsMu.Unlock()
		return append([]string(nil), operations...)
	}
	return got, operationSnapshot, ctx, client, cancel
}

func assertConfirmOffDispatch(t *testing.T, ctx context.Context, client *broker.Client, operations func() []string) {
	t.Helper()
	descriptor := broker.Descriptor{Mode: broker.ModeFull, Protocol: broker.FullProtocol, Complete: true, Tools: []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel", "remote_upload", "remote_download", "transfer_status", "transfer_cancel"}}
	server, err := bridge.NewRegistryForDescriptorWithConfirm(client, descriptor, nil)
	if err != nil {
		t.Fatal("could not build confirm-off bridge registry")
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	session, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal("could not connect in-memory MCP server")
	}
	t.Cleanup(func() { session.Close() })
	conn, err := clientTransport.Connect(ctx)
	if err != nil {
		t.Fatal("could not connect raw in-memory MCP client")
	}
	t.Cleanup(func() { conn.Close() })
	initialize, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"confirm-off-test","version":"1"}}}`))
	if err != nil {
		t.Fatal("could not decode MCP initialize")
	}
	if err := conn.Write(ctx, initialize); err != nil {
		t.Fatal("could not send MCP initialize")
	}
	if _, err := conn.Read(ctx); err != nil {
		t.Fatal("could not read MCP initialize response")
	}
	initialized, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatal("could not decode MCP initialized notification")
	}
	if err := conn.Write(ctx, initialized); err != nil {
		t.Fatal("could not send MCP initialized notification")
	}
	call, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remote_upload","arguments":{"target":"synthetic-target","local":"synthetic-file","remote":"/tmp/synthetic"}}}`))
	if err != nil {
		t.Fatal("could not decode remote_upload call")
	}
	if err := conn.Write(ctx, call); err != nil {
		t.Fatal("could not send remote_upload call")
	}
	response, err := conn.Read(ctx)
	if err != nil {
		t.Fatal("could not read remote_upload result")
	}
	encoded, err := jsonrpc.EncodeMessage(response)
	if err != nil {
		t.Fatal("could not encode remote_upload result")
	}
	var envelope struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal("could not decode remote_upload result")
	}
	if len(envelope.Error) != 0 || envelope.Result.IsError || len(envelope.Result.Content) == 0 || !strings.HasPrefix(envelope.Result.Content[0].Text, "Started job ") {
		t.Fatalf("remote_upload did not normally dispatch with confirmation OFF: %s", encoded)
	}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline) && len(operations()) < 2; {
		time.Sleep(time.Millisecond)
	}
	current := operations()
	if len(current) != 2 || current[1] != "transfer_upload" {
		t.Fatalf("keeper operations = %v, want confirm_config and one transfer_upload", current)
	}
}
