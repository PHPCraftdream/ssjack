package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
	"github.com/PHPCraftdream/ssjack/internal/lifelog"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
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
	assertBootstrapKeeperCounts(t, &countsMu, counts, &attachedEvents, 1, 0)

	writeMCPFrame(t, clientIn, `{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{`+meta+`}}`)
	secondDiscover := sdkCallResults(t, readMCPLine(t, clientOut), false, 2)[2]
	assertBootstrapProtocolDiscover(t, secondDiscover)
	assertBootstrapKeeperCounts(t, &countsMu, counts, &attachedEvents, 1, 0)
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
	structured, ok := called["structuredContent"].(map[string]any)
	targets, targetsOK := structured["targets"].([]any)
	if called["isError"] == true || !ok || !targetsOK || len(targets) != 1 || targets[0] != "synthetic-target" {
		t.Fatal("remote_targets did not return the attached keeper result")
	}
	assertBootstrapKeeperCounts(t, &countsMu, counts, &attachedEvents, 1, 1)

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

func assertBootstrapKeeperCounts(t *testing.T, mu *sync.Mutex, counts map[string]int, attachedEvents *int, describes, targets int) {
	t.Helper()
	mu.Lock()
	wantOperations := 0
	if describes != 0 {
		wantOperations++
	}
	if targets != 0 {
		wantOperations++
	}
	if counts["session.describe"] != describes || counts["targets"] != targets || len(counts) != wantOperations || *attachedEvents != 1 {
		mu.Unlock()
		t.Fatal("discovery caused an unexpected keeper operation")
	}
	mu.Unlock()
}
