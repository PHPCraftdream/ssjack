package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
	ssh "golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/remotemcp"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/sshfixture"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrpc"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// ownerCloseFunc adapts a closure to the OwnerSession interface.
type ownerCloseFunc func(context.Context) error

func (f ownerCloseFunc) Close(ctx context.Context) error { return f(ctx) }

type stubUp struct{}

type emptyChannelHandler struct{}

func (emptyChannelHandler) Describe(context.Context) ([]byte, error) { return []byte(`{}`), nil }
func (emptyChannelHandler) Call(context.Context, string, []byte) ([]byte, error) {
	return []byte(`{}`), nil
}

func (stubUp) TakeTransport() (mcp.Transport, error) {
	return nil, errors.New("unused in finish tests")
}

// bridgeRuntimeFixture builds a real bridge runtime around a stub upstream so
// finish-order tests exercise the actual Close path.
func bridgeRuntimeFixture(t *testing.T, closeLaunch func(context.Context) error) *mcpbridge.Runtime {
	t.Helper()
	guard, err := outputguard.New(nil) // empty pattern set is valid
	if err != nil {
		t.Fatal(err)
	}
	rt, err := mcpbridge.Open(context.Background(), []mcpbridge.UpstreamHandle{stubUp{}}, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := rt.Close(ctx); err != nil {
			t.Errorf("bridge fixture cleanup did not join: %v", err)
		}
	})
	return rt
}

func TestWithMCPLaunchIsOneShotAndKeepsCleanupOwnership(t *testing.T) {
	launch := &mcpgrant.Launch{}
	credentials := &Credentials{mcpLaunch: launch}
	calls := 0
	if err := credentials.withMCPLaunch(func(got *mcpgrant.Launch) error {
		calls++
		if got != launch {
			t.Fatal("callback received a different launch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || credentials.mcpLaunch != launch {
		t.Fatal("launch access consumed the owned cleanup handle")
	}
	if err := credentials.withMCPLaunch(func(*mcpgrant.Launch) error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatal("launch callback was not one-shot")
	}
}

func TestWithMCPLaunchMarksAttemptConsumedWhenCallbackFails(t *testing.T) {
	launch := &mcpgrant.Launch{}
	credentials := &Credentials{mcpLaunch: launch}
	failure := errors.New("synthetic callback failure")
	if err := credentials.withMCPLaunch(func(*mcpgrant.Launch) error { return failure }); !errors.Is(err, failure) {
		t.Fatal("callback error was not returned")
	}
	if credentials.mcpLaunch != launch {
		t.Fatal("callback failure dropped cleanup ownership")
	}
	if err := credentials.withMCPLaunch(func(*mcpgrant.Launch) error { return nil }); err == nil {
		t.Fatal("failed callback left launch access reusable")
	}
}

func TestFinishAgentCredentialsRetainsFailedLaunchCleanup(t *testing.T) {
	launch := &mcpgrant.Launch{}
	ownerCloses := 0
	credentials := &Credentials{
		mcpLaunch: launch,
		owner: ownerCloseFunc(func(errorContext context.Context) error {
			ownerCloses++
			return nil
		}),
	}
	code := 0
	var result error
	credentials.Finish(&code, &result)
	if code != 1 || !errors.Is(result, errOwnerShutdown) {
		t.Fatal("failed launch cleanup was not reported")
	}
	if credentials.mcpLaunch != launch || ownerCloses != 0 {
		t.Fatal("failed launch cleanup was dropped or owner closed prematurely")
	}
}

func TestFinishAgentCredentialsClosesChannelsBeforeBridge(t *testing.T) {
	channels, err := mcpchannel.Open(context.Background(), 1, time.Minute, func(int) mcpchannel.Handler { return emptyChannelHandler{} })
	if err != nil {
		t.Fatal("could not open owned channel fixture")
	}
	bridgeClosed := false
	runtime := bridgeRuntimeFixture(t, func(context.Context) error {
		select {
		case <-channels.Done():
		default:
			t.Fatal("bridge close ran before owned channels joined")
		}
		bridgeClosed = true
		return nil
	})
	credentials := &Credentials{channels: channels, mcpBridge: runtime, mcpLaunch: &mcpgrant.Launch{}, mcpLaunchUsed: true}
	code := 0
	var result error
	credentials.Finish(&code, &result)
	if code != 0 || result != nil || !bridgeClosed || credentials.channels != nil || credentials.mcpBridge != nil {
		t.Fatal("credential cleanup did not join channels before the bridge")
	}
}

func TestFinishAgentCredentialsClosesBridgeBeforeOwner(t *testing.T) {
	sequence := 0
	closeRun, ownerRun := 0, 0
	var bridgeClosed bool
	credentials := &Credentials{
		mcpBridge: bridgeRuntimeFixture(t, func(context.Context) error {
			sequence++
			closeRun = sequence
			bridgeClosed = true
			return nil
		}),
		mcpLaunch:     &mcpgrant.Launch{},
		mcpLaunchUsed: true,
		owner: ownerCloseFunc(func(context.Context) error {
			if !bridgeClosed {
				t.Fatal("owner close ran before bridge session joined")
			}
			sequence++
			ownerRun = sequence
			return nil
		}),
	}
	code := 0
	var result error
	credentials.Finish(&code, &result)
	if code != 0 || result != nil {
		t.Fatal("successful bridge close was reported as a failure")
	}
	if closeRun != 1 || ownerRun != 2 {
		t.Fatal("bridge or owner close did not run exactly once")
	}
	if ownerRun <= closeRun {
		t.Fatal("owner closed before the bridge")
	}
	if credentials.mcpBridge != nil || credentials.mcpLaunch != nil {
		t.Fatal("bridge close did not clear the bridge and launch handles")
	}
}

func TestFinishAgentCredentialsRetainsFailedBridgeCleanup(t *testing.T) {
	closeCalls := 0
	closeLaunch := func(context.Context) error {
		closeCalls++
		if closeCalls == 1 {
			return errors.New("synthetic bridge close failure")
		}
		return nil
	}
	rt := bridgeRuntimeFixture(t, closeLaunch)
	credentials := &Credentials{
		mcpBridge:     rt,
		mcpLaunch:     &mcpgrant.Launch{},
		mcpLaunchUsed: true,
		owner: ownerCloseFunc(func(context.Context) error {
			t.Fatal("owner must not close after a failed bridge cleanup")
			return nil
		}),
	}
	code := 0
	var result error
	credentials.Finish(&code, &result)
	if code != 1 || !errors.Is(result, errOwnerShutdown) {
		t.Fatal("failed bridge cleanup was not reported")
	}
	if credentials.mcpBridge == nil {
		t.Fatal("failed bridge cleanup dropped the retained bridge state")
	}
}

func TestBridgeConsumesLaunchOneShotAccess(t *testing.T) {
	credentials := &Credentials{
		mcpBridge:     bridgeRuntimeFixture(t, func(context.Context) error { return nil }),
		mcpLaunch:     &mcpgrant.Launch{},
		mcpLaunchUsed: true,
	}
	if err := credentials.withMCPLaunch(func(*mcpgrant.Launch) error { return nil }); err == nil || err.Error() != "remote MCP launch is unavailable" {
		t.Fatal("active bridge did not refuse direct launch access")
	}
}

func assertGuardMasks(t *testing.T, snapshot *outputguard.Snapshot, value []byte) {
	t.Helper()
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &result)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range value {
		if _, err := writer.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil || result.String() != outputguard.Marker {
		t.Fatal("startup guard did not retain the captured credential")
	}
}

func TestFixedGuardRefusesMissingSeedAndCancelledAdmission(t *testing.T) {
	if snapshot, err := FixedOutputGuard(nil)(context.Background()); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("missing startup seed granted an unguarded capability")
	}
	snapshot, err := outputguard.New([][]byte{[]byte("synthetic captured credential")})
	if err != nil {
		t.Fatal(err)
	}
	provider := FixedOutputGuard(snapshot)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if result, err := provider(ctx); result != nil || err != outputguard.ErrGuard {
			t.Fatal("invalid context obtained a captured capability")
		}
	}
	captured, err := provider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertGuardMasks(t, captured, []byte("synthetic captured credential"))
}

type serviceCloseProbe struct {
	close func(context.Context) error
	done  chan struct{}
}

func (p *serviceCloseProbe) Close(ctx context.Context) error { return p.close(ctx) }
func (p *serviceCloseProbe) Done() <-chan struct{}           { return p.done }

func TestKeeperJoinsServiceBeforeClosingParentKeyAndRole(t *testing.T) {
	for _, mode := range []string{"joined", "service-error", "unjoined", "partial-service"} {
		t.Run(mode, func(t *testing.T) {
			var events []string
			private := errors.New("synthetic-private-service-diagnostic")
			service := &serviceCloseProbe{done: make(chan struct{})}
			service.close = func(ctx context.Context) error {
				events = append(events, "service-close")
				if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
					t.Fatal("service cleanup omitted independent bound")
				}
				if mode != "unjoined" {
					close(service.done)
				}
				if mode == "service-error" || mode == "unjoined" {
					return private
				}
				return nil
			}
			credentials := &Credentials{service: service, owner: ownerCloseFunc(func(context.Context) error {
				events = append(events, "owner-close")
				return nil
			})}
			if mode == "partial-service" {
				credentials.owner = nil
			}
			code := 0
			var result error
			credentials.Finish(&code, &result)
			want := []string{"service-close", "owner-close"}
			if mode == "unjoined" || mode == "partial-service" {
				want = want[:1]
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatal("parent closed before service join or partial service leaked")
			}
			if mode == "service-error" || mode == "unjoined" {
				if code != 1 || !errors.Is(result, errOwnerShutdown) || strings.Contains(result.Error(), private.Error()) {
					t.Fatal("unsafe service shutdown reported success or raw diagnostics")
				}
			} else if code != 0 || result != nil {
				t.Fatal("joined service changed a saved outcome")
			}
		})
	}
}

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
			_, runErr := remotemcp.Run(context.Background())
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
	_, runErr := remotemcp.Run(context.Background())
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
		return broker.Result(broker.Descriptor{Protocol: broker.FullProtocol, Mode: broker.ModeFull, Complete: true, Tools: []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel", "remote_upload", "remote_download", "transfer_status", "transfer_cancel"}}, nil)
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
	_, runErr := remotemcp.Run(context.Background())
	if runErr == nil || runErr.Error() != "MCP bridge session failed" {
		t.Fatalf("canonical config did not reach expected stdio completion: %v", runErr)
	}
	select {
	case <-keeper.Attached():
	default:
		t.Fatal("canonical fixed config failed to attach to the local keeper")
	}
}

func makeRemoteMCPChannelCredentials(t *testing.T, known remote.GuardProvider) *Credentials {
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
	credentials := &Credentials{mcpBridge: runtime, mcpLaunch: launch, mcpLaunchUsed: true, guard: known, capture: capture}
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
	credentials := makeRemoteMCPChannelCredentials(t, FixedOutputGuard(known))
	combined, _, err := credentials.PrepareRemoteMCPChannels(context.Background(), credentials.guard, time.Minute)
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
	credentials := makeRemoteMCPChannelCredentials(t, FixedOutputGuard(empty))
	combined, _, err := credentials.PrepareRemoteMCPChannels(context.Background(), credentials.guard, time.Minute)
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

func TestVaultKeeperLifetimeFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production keeper ownership acceptance is CI-only")
	}
	for _, directory := range []bool{true, false} {
		name := "legacy"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) { keeperLifetimeAcceptance(t, directory) })
	}
}

func keeperLifetimeAcceptance(t *testing.T, directory bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	server := sshfixture.StartLoopbackSSH(t, public, sshfixture.ConnectPassword, "keeper-lifetime")
	v := vault.New()
	if directory {
		v = vault.NewDirectory()
	}
	defer v.Close()
	target := vault.Target{Address: server.Address(), User: "second", Password: []byte(sshfixture.ConnectPassword), HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.HostKey))}, Usage: "agent"}
	defer clear(target.Password)
	expectedAuthentication := "second|password"
	if !directory {
		block, err := ssh.MarshalPrivateKey(private, "synthetic keeper lifetime fixture")
		if err != nil {
			t.Fatal(err)
		}
		defer clear(block.Bytes)
		target.User, target.Password, target.PrivateKey = "first", nil, pem.EncodeToMemory(block)
		defer clear(target.PrivateKey)
		expectedAuthentication = "first|publickey"
	}
	selection, serverID := "main", ""
	if directory {
		serverID, err = v.AddServer("production", "main", target)
		if err != nil {
			t.Fatal(err)
		}
		selection = "@production/main"
	} else {
		v.Targets["main"] = target
	}
	password := []byte("synthetic keeper lifetime database password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "keeper.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	source := startupsecret.New(string(password), true)
	defer source.Close()
	ctx = startup.WithInput(ctx, source)
	credentials, err := Load(ctx, path, selection)
	if err != nil || credentials == nil || len(credentials.targets) != 1 {
		t.Fatal("keeper failed to capture its selected credentials")
	}
	if _, err := source.Read(func() ([]byte, error) { t.Fatal("keeper requested another password"); return nil, nil }); !errors.Is(err, startupsecret.ErrConsumed) {
		t.Fatal("keeper startup did not consume exactly one password source")
	}
	var manager *ownerdb.Manager
	defer func() {
		cleanupCode := 0
		var cleanupError error
		credentials.Finish(&cleanupCode, &cleanupError)
		if credentials.service != nil {
			select {
			case <-credentials.service.Done():
			default:
				t.Error("keeper fixture still has unfinished peers")
				return
			}
		}
		if manager != nil {
			manager.Discard()
		}
	}()
	if credentials.guard == nil {
		t.Fatal("authenticated startup omitted its private guard provider")
	}
	initialGuard, err := credentials.guard(ctx)
	if err != nil {
		t.Fatal("authenticated startup failed to seed its private guard")
	}
	credential := target.Password
	if !directory {
		credential = target.PrivateKey
	}
	assertGuardMasks(t, initialGuard, credential)
	if directory {
		var ok bool
		manager, ok = credentials.owner.(*ownerdb.Manager)
		if !ok || manager == nil || credentials.service == nil {
			t.Fatal("directory keeper discarded its authenticated owner session or service")
		}
		binding, err := manager.OwnerBinding()
		if err != nil {
			t.Fatal(err)
		}
		connection, err := ownerlocal.Dial(ctx, path)
		if err != nil {
			t.Fatal("keeper did not start its owned service")
		}
		packet, err := manager.LocalOwnerPeer(binding)
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		client, err := ownerrpc.Attach(ctx, connection, packet)
		if err != nil {
			t.Fatal("keeper service did not authenticate its retained context")
		}
		reply, err := client.Execute(ctx, ownerpacket.Command{Operation: "snapshot"})
		client.Close()
		if err != nil || reply.CipherDigest == ([32]byte{}) {
			t.Fatal("keeper startup service omitted saved metadata")
		}
		snapshot, err := manager.Snapshot()
		if err != nil || snapshot.CipherDigest == ([32]byte{}) {
			t.Fatal("retained owner has no authenticated saved snapshot")
		}
		err = manager.EditAt(snapshot.Status.Database.Revision, func(candidate *vault.Vault) error {
			profile, err := candidate.AccountProfile(serverID, "main")
			if err != nil {
				return err
			}
			changed := candidate.Targets[profile]
			changed.Address, changed.User, changed.Usage = "127.0.0.1:1", "edited", "human"
			changed.Password = []byte("synthetic rotated keeper password")
			candidate.Targets[profile] = changed
			return nil
		})
		if err != nil || manager.Flush(ctx) != nil {
			t.Fatal("retained owner could not edit and save without another unlock")
		}
		currentGuard, err := credentials.guard(ctx)
		if err != nil {
			t.Fatal("startup provider did not adopt confirmed owner state")
		}
		assertGuardMasks(t, currentGuard, credential)
		assertGuardMasks(t, currentGuard, []byte("synthetic rotated keeper password"))
		verifyKeeperMCPPreference(t, ctx, manager, credentials.targets[0])
	} else if credentials.owner != nil || credentials.service != nil {
		t.Fatal("legacy startup silently created an unsupported directory coordinator")
	}
	// The shell-only fixture refuses exec after authenticating the frozen config.
	if _, err := credentials.runner(ctx, credentials.targets[0], "true", io.Discard, io.Discard); err == nil {
		t.Fatal("shell-only fixture unexpectedly accepted exec")
	}
	if !reflect.DeepEqual(server.Authentications(), []string{expectedAuthentication}) {
		t.Fatal("keeper runner adopted later database edits or borrowed cleared credentials")
	}
	code := 0
	var outcome error
	credentials.Finish(&code, &outcome)
	if code != 0 || outcome != nil {
		t.Fatal("keeper did not close its saved owner session")
	}
	if manager != nil {
		if _, err := manager.Metadata(); err == nil {
			t.Fatal("keeper shutdown left its owner session available")
		}
	}
	encoded, err := os.ReadFile(path)
	if err != nil || bytes.Contains(encoded, password) || bytes.Contains(encoded, []byte(sshfixture.ConnectPassword)) {
		t.Fatal("keeper persisted plaintext credential material")
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal("keeper database did not authenticate after shutdown")
	}
	defer loaded.Close()
	if directory {
		if snapshot, err := loaded.LegacyOutputGuard(ctx, path); snapshot != nil || err != outputguard.ErrGuard {
			t.Fatal("directory startup bypassed linked-value guard admission")
		}
		profile, err := loaded.AccountProfile(serverID, "main")
		if err != nil || loaded.Targets[profile].User != "edited" || loaded.Targets[profile].Usage != "human" || loaded.RemoteMCP == nil || len(loaded.RemoteMCP.Last[profile]) != 1 {
			t.Fatal("retained owner changes did not survive keeper shutdown")
		}
	} else {
		if loaded.Targets["main"].User != "first" {
			t.Fatal("legacy read-only startup changed its record")
		}
		captured, err := loaded.LegacyOutputGuard(ctx, path)
		if err != nil {
			t.Fatal("unchanged authenticated legacy state refused capture")
		}
		changed := loaded.Targets["main"]
		changed.User = "changed"
		loaded.Targets["main"] = changed
		if snapshot, err := loaded.LegacyOutputGuard(ctx, path); snapshot != nil || err != outputguard.ErrGuard {
			t.Fatal("modified legacy state granted an authenticated capture")
		}
		loaded.Close()
		assertGuardMasks(t, captured, credential)
	}
}

func verifyKeeperMCPPreference(t *testing.T, ctx context.Context, manager *ownerdb.Manager, profile string) {
	t.Helper()
	var binding mcpdirectory.Binding
	if err := manager.Edit(func(v *vault.Vault) error {
		v.RemoteMCP = mcpdirectory.New()
		server, err := v.RemoteMCP.AddServer("keeper-preference", "https://preference.invalid/mcp")
		if err != nil {
			return err
		}
		account, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: server, Name: "public", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "none"}})
		if err == nil {
			binding, err = v.RemoteMCP.CurrentBinding(account)
		}
		return err
	}); err != nil || manager.Flush(ctx) != nil {
		t.Fatal("keeper preference fixture could not persist its MCP metadata")
	}
	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	digest, revision := snapshot.CipherDigest, snapshot.Status.Database.Revision
	wrong := digest
	wrong[0] ^= 128
	if manager.RememberRemoteMCPAt(ctx, revision, wrong, profile, []mcpdirectory.Binding{binding}) == nil {
		t.Fatal("changed ciphertext evidence admitted a preference")
	}
	selected := []mcpdirectory.Binding{binding}
	if err := manager.RememberRemoteMCPAt(ctx, revision, digest, profile, selected); err != nil {
		t.Fatal("confirmed keeper preference was refused")
	}
	selected[0].AccountRevision++
	if manager.Flush(ctx) != nil {
		t.Fatal("keeper preference did not persist with retained contexts")
	}
	metadata, err := manager.Metadata()
	if err != nil || !reflect.DeepEqual(metadata.RemoteMCP.Last[profile], []mcpdirectory.Binding{binding}) {
		t.Fatal("keeper preference borrowed input or lost its exact binding")
	}
	if manager.RememberRemoteMCPAt(ctx, revision, digest, profile, nil) == nil {
		t.Fatal("old displayed revision changed a confirmed preference")
	}
}

// TestFullStartupRoutesModelOutputThroughRequiredGuard mirrors the full
// startup wiring of cli.startFullMode in-process: a real Credentials value,
// PrepareRemoteMCPChannels, PrepareMCPBootstrapOutput and Credentials.Manager.
// If production ever selects an unguarded manager, the raw model bytes below
// reach the captured output and fail these assertions.
func TestFullStartupRoutesModelOutputThroughRequiredGuard(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "guarded", true: "missing"}[missing], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			snapshot, err := outputguard.New([][]byte{[]byte("synthetic-model-secret"), {0, 255, 'b'}})
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			runner := func(_ context.Context, _, _ string, stdout, stderr io.Writer) (int, error) {
				calls.Add(1)
				for _, value := range []byte("synthetic-model-secret|\x00\xffb|public\xfe") {
					if _, err := stdout.Write([]byte{value}); err != nil {
						return -1, err
					}
				}
				_, err := stderr.Write([]byte("synthetic-model-secret"))
				return 19, err
			}
			guard := FixedOutputGuard(snapshot)
			if missing {
				guard = nil
			}
			credentials := &Credentials{runner: runner, guard: guard, targets: []string{"test"}}
			known, _, err := credentials.PrepareRemoteMCPChannels(ctx, credentials.guard, time.Minute)
			if err != nil {
				t.Fatal("channel preparation failed without an active bridge")
			}
			provider, setup := PrepareMCPBootstrapOutput(ctx, known, credentials.Bridge())
			setupErr := setup(snapshot)
			if (missing && setupErr == nil) || (!missing && setupErr != nil) {
				t.Fatal("bootstrap output setup did not match the expected guard state")
			}
			manager := credentials.Manager(ctx, credentials.Targets(), provider, false)
			defer manager.Close()
			started, err := manager.Start(remote.StartInput{Target: "test", Command: "synthetic"})
			if err != nil {
				t.Fatal("required manager refused a permitted start")
			}
			var out remote.ReadOutput
			flakediag.WaitFor(t, "guarded keeper job completion", 5*time.Second, func() (string, bool) {
				var err error
				out, err = manager.Read(remote.ReadInput{JobID: started.JobID})
				if err != nil {
					t.Fatal(err)
				}
				return "job still running", out.Done
			})
			if !out.Done {
				t.Fatal("required manager job did not finish")
			}
			if missing {
				if calls.Load() != 0 || out.Error != outputguard.ErrGuard.Error() || len(out.Stdout)+len(out.Stderr) != 0 {
					t.Fatal("missing startup guard executed a model job")
				}
			} else if calls.Load() != 1 || out.ExitCode != 19 || out.Error != "" || !bytes.Equal(out.Stdout, []byte("[REDACTED]|[REDACTED]|public\xfe")) || string(out.Stderr) != outputguard.Marker {
				t.Fatal("real manager captured original model bytes or changed control fields")
			}
		})
	}
}
