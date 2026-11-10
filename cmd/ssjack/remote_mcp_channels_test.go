package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestRunMCPPreflightRefusesConfigCasesAndLeavesKeeperAvailable(t *testing.T) {
	for name, config := range map[string]string{
		"env-present":          `{"mcpServers":{"ssjack":{"type":"stdio","command":"ssjack","args":["mcp"],"env":null}}}`,
		"cwd-present":          `{"mcpServers":{"ssjack":{"type":"stdio","command":"ssjack","args":["mcp"],"cwd":null}}}`,
		"foreign-command":      `{"mcpServers":{"ssjack":{"type":"stdio","command":"other","args":["mcp"]}}}`,
		"malformed-json":       `{"mcpServers":`,
		"duplicate-field":      `{"mcpServers":{"ssjack":{"command":"ssjack","command":"ssjack","args":["mcp"]}}}`,
		"case-duplicate-field": `{"mcpServers":{"ssjack":{"command":"ssjack","Command":"ssjack","args":["mcp"]}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(root)
			session, token := strings.Repeat("1", 64), strings.Repeat("2", 64)
			keeper, err := broker.Listen(context.Background(), session, token, time.Minute, func(context.Context, wire.Request) wire.Reply {
				return broker.Result(map[string]any{}, nil)
			})
			if err != nil {
				t.Fatal("local synthetic keeper unavailable")
			}
			defer keeper.Close()
			t.Setenv(broker.EnvSession, session)
			t.Setenv(broker.EnvToken, token)
			t.Setenv(broker.EnvEndpoint, keeper.Endpoint())
			t.Setenv(broker.EnvPin, keeper.Pin())
			t.Setenv(broker.EnvFile, "stale-bootstrap-file")
			t.Setenv("SSJACK_APP_ENDPOINT", "stale-app-endpoint")
			t.Setenv("SSJACK_APP_TOKEN", "stale-app-token")
			t.Setenv("SSJACK_APP_CERTIFICATE_SHA256", "stale-app-pin")
			t.Setenv(mcpchannel.Env, "")
			if err := os.Unsetenv(mcpchannel.Env); err != nil {
				t.Fatal("could not clear channel descriptors")
			}
			_, runErr := runMCP(context.Background())
			if runErr == nil || runErr.Error() != "MCP bridge requires an accepted entry in fixed .mcp.json" {
				t.Fatal("fixed config did not refuse before keeper work")
			}
			for _, key := range []string{broker.EnvSession, broker.EnvToken, broker.EnvEndpoint, broker.EnvPin, broker.EnvFile, mcpchannel.Env, "SSJACK_APP_ENDPOINT", "SSJACK_APP_TOKEN", "SSJACK_APP_CERTIFICATE_SHA256"} {
				if _, exists := os.LookupEnv(key); exists {
					t.Fatalf("reserved environment survived refusal: %s", key)
				}
			}
			select {
			case <-keeper.Attached():
				t.Fatal("preflight refusal consumed the keeper")
			default:
			}
		})
	}
}

func TestRunMCPMalformedChannelsScrubBootstrapBeforeRefusal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"ssjack":{"command":"ssjack","args":["mcp"]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	session, token := strings.Repeat("5", 64), strings.Repeat("6", 64)
	keeper, err := broker.Listen(context.Background(), session, token, time.Minute, func(context.Context, wire.Request) wire.Reply {
		return wire.Reply{OK: true}
	})
	if err != nil {
		t.Fatal("local synthetic keeper unavailable")
	}
	defer keeper.Close()
	t.Setenv(broker.EnvSession, session)
	t.Setenv(broker.EnvToken, token)
	t.Setenv(broker.EnvEndpoint, keeper.Endpoint())
	t.Setenv(broker.EnvPin, keeper.Pin())
	t.Setenv(broker.EnvFile, "stale-bootstrap-file")
	t.Setenv("SSJACK_APP_ENDPOINT", "stale-app-endpoint")
	t.Setenv("SSJACK_APP_TOKEN", "stale-app-token")
	t.Setenv("SSJACK_APP_CERTIFICATE_SHA256", "stale-app-pin")
	t.Setenv(mcpchannel.Env, "malformed")
	_, runErr := runMCP(context.Background())
	if runErr == nil || runErr.Error() != "remote MCP channel descriptors are invalid" {
		t.Fatal("malformed channels did not refuse before keeper work")
	}
	for _, key := range []string{broker.EnvFile, broker.EnvSession, broker.EnvToken, broker.EnvEndpoint, broker.EnvPin, mcpchannel.Env,
		"SSJACK_APP_ENDPOINT", "SSJACK_APP_TOKEN", "SSJACK_APP_CERTIFICATE_SHA256"} {
		if _, exists := os.LookupEnv(key); exists {
			t.Fatalf("reserved environment survived refusal: %s", key)
		}
	}
	select {
	case <-keeper.Attached():
		t.Fatal("malformed channel refusal consumed the keeper")
	default:
	}
}

func TestRunMCPCanonicalFixedConfigReachesSyntheticKeeper(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"other":{"command":"preserved"},"ssjack":{"type":"stdio","command":"ssjack","args":["mcp"]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	session, token := strings.Repeat("3", 64), strings.Repeat("4", 64)
	keeper, err := broker.Listen(context.Background(), session, token, time.Minute, func(_ context.Context, request wire.Request) wire.Reply {
		if request.Operation != "session.describe" {
			return wire.Reply{Error: "unexpected operation"}
		}
		return broker.Result(broker.Descriptor{Protocol: broker.FullProtocol, Mode: broker.ModeFull, Complete: true, Tools: []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel"}}, nil)
	})
	if err != nil {
		t.Fatal("local synthetic keeper unavailable")
	}
	defer keeper.Close()
	t.Setenv(broker.EnvSession, session)
	t.Setenv(broker.EnvToken, token)
	t.Setenv(broker.EnvEndpoint, keeper.Endpoint())
	t.Setenv(broker.EnvPin, keeper.Pin())
	t.Setenv(mcpchannel.Env, "")
	if err := os.Unsetenv(mcpchannel.Env); err != nil {
		t.Fatal("could not clear channel descriptors")
	}
	input, err := os.CreateTemp(root, "mcp-stdin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.WriteString("not-json\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previous := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previous }()
	previousOut := os.Stdout
	output, err := os.CreateTemp(root, "mcp-stdout")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = output
	defer func() { os.Stdout = previousOut; output.Close() }()
	_, runErr := runMCP(context.Background())
	if runErr == nil || runErr.Error() != "MCP bridge session failed" {
		t.Fatalf("canonical config did not reach expected stdio completion: %v", runErr)
	}
	select {
	case <-keeper.Attached():
	default:
		t.Fatal("canonical fixed config failed to attach to the local keeper")
	}
}

func makeRemoteMCPChannelCredentials(t *testing.T, known remote.GuardProvider) *agentCredentials {
	t.Helper()
	ctx := context.Background()
	directory := mcpdirectory.New()
	serverID, err := directory.AddServer("fixture", "https://example.com/mcp")
	if err != nil {
		t.Fatal("could not create inert server fixture")
	}
	account := mcpdirectory.Account{ServerID: serverID, Name: "fixture-account", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-upstream-auth-literal")}}
	accountID, err := directory.AddAccount(account)
	if err != nil {
		t.Fatal("could not create inert account fixture")
	}
	server, stored := directory.Servers[serverID], directory.Accounts[accountID]
	capture, err := mcpgrant.NewCapture(ctx, "fixture-profile", 1, [32]byte{1}, []mcpgrant.Record{{ServerID: serverID, AccountID: accountID, Server: server, Account: stored}})
	if err != nil {
		t.Fatal("could not capture inert launch fixture")
	}
	binding := mcpdirectory.Binding{ServerID: serverID, AccountID: accountID, ServerRevision: server.Revision, AccountRevision: stored.Revision}
	launch, err := capture.Issue(ctx, "fixture-profile", 1, []mcpdirectory.Binding{binding})
	if err != nil {
		t.Fatal("could not mint inert launch fixture")
	}
	guard, err := outputguard.New(nil)
	if err != nil {
		t.Fatal("could not create empty bridge guard")
	}
	runtime, err := mcpbridge.Open(ctx, []mcpbridge.UpstreamHandle{&mcpbridge.LaunchUpstream{Upstream: launch.Upstreams()[0]}}, guard, func(closeCtx context.Context) error { return launch.Close(closeCtx) }, []mcpdirectory.Binding{binding})
	if err != nil {
		t.Fatal("could not open bridge fixture")
	}
	credentials := &agentCredentials{mcpBridge: runtime, mcpLaunch: launch, mcpLaunchUsed: true, guard: known, capture: capture}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if credentials.channels != nil {
			if err := credentials.channels.Close(cleanupCtx); err != nil {
				t.Errorf("channel cleanup did not join: %v", err)
			}
			credentials.channels = nil
		}
		if err := runtime.Close(cleanupCtx); err != nil {
			t.Errorf("bridge cleanup did not join: %v", err)
		}
		if err := capture.Close(cleanupCtx); err != nil {
			t.Errorf("capture cleanup did not complete: %v", err)
		}
	})
	return credentials
}

func applyRemoteMCPGuard(t *testing.T, guard *outputguard.Snapshot, input string) string {
	t.Helper()
	var output bytes.Buffer
	writer, err := outputguard.NewWriter(guard, &output)
	if err != nil {
		t.Fatal("guard writer creation failed")
	}
	if _, err := writer.Write([]byte(input)); err != nil {
		t.Fatal("guard writer rejected fixture")
	}
	if err := writer.Close(); err != nil {
		t.Fatal("guard writer did not close")
	}
	return output.String()
}

func TestPrepareRemoteMCPChannelsUnionsMandatoryGuardWithKnownOutput(t *testing.T) {
	known, err := outputguard.New([][]byte{[]byte("synthetic-ssh-key-literal"), []byte("synthetic-upstream-auth-literal")})
	if err != nil {
		t.Fatal("could not create known output guard")
	}
	credentials := makeRemoteMCPChannelCredentials(t, fixedOutputGuard(known))
	combined, _, err := prepareRemoteMCPChannels(context.Background(), credentials, credentials.guard, time.Minute)
	if err != nil {
		t.Fatal("channel setup refused a valid minted capability")
	}
	snapshot, err := combined(context.Background())
	if err != nil {
		t.Fatal("combined output guard was unavailable")
	}
	masked := applyRemoteMCPGuard(t, snapshot, "synthetic-ssh-key-literal synthetic-upstream-auth-literal "+credentials.channels.Descriptors()[0].Token)
	if strings.Contains(masked, "synthetic-ssh-key-literal") || strings.Contains(masked, "synthetic-upstream-auth-literal") || strings.Contains(masked, credentials.channels.Descriptors()[0].Token) || strings.Count(masked, outputguard.Marker) != 3 {
		t.Fatal("channel preparation dropped a pre-existing output literal")
	}
}

func TestPrepareRemoteMCPChannelsKeepsMandatoryGuardWhenKnownOutputEmpty(t *testing.T) {
	empty, err := outputguard.New(nil)
	if err != nil {
		t.Fatal("could not create empty known guard")
	}
	credentials := makeRemoteMCPChannelCredentials(t, fixedOutputGuard(empty))
	combined, _, err := prepareRemoteMCPChannels(context.Background(), credentials, credentials.guard, time.Minute)
	if err != nil {
		t.Fatal("channel setup refused an empty known output guard")
	}
	snapshot, err := combined(context.Background())
	if err != nil {
		t.Fatal("combined output guard was unavailable")
	}
	descriptors := credentials.channels.Descriptors()
	if len(descriptors) != 1 || descriptors[0].Token == "" {
		t.Fatal("channel capability fixture was not created")
	}
	// No-output-filter selection suppresses known output literals, not the
	// private loopback channel token guard.
	masked := applyRemoteMCPGuard(t, snapshot, "synthetic-ssh-key-literal "+descriptors[0].Token+" ordinary-visible-text")
	if masked != "synthetic-ssh-key-literal "+outputguard.Marker+" ordinary-visible-text" {
		t.Fatal("empty known-output filtering bypassed mandatory local channel redaction or changed ordinary output")
	}
}
