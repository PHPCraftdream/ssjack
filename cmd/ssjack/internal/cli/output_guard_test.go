package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/agent"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/launchguard"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/childdiag"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

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

type stubUp struct{}

func (stubUp) TakeTransport() (mcp.Transport, error) {
	return nil, errors.New("unused in finish tests")
}

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

func guardedHandlerCall(t *testing.T, ctx context.Context, handler broker.Handler, operation string, input, output any) {
	t.Helper()
	data, err := wire.Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	reply := handler(ctx, wire.Request{Operation: operation, Data: data})
	if !reply.OK || wire.Decode(reply.Data, output) != nil {
		t.Fatal("guarded keeper operation failed")
	}
}

func outputguardSnapshot(t *testing.T) *outputguard.Snapshot {
	t.Helper()
	snapshot, err := outputguard.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestOutputFilterChoiceDefaultsToOriginalGuardAndWarnsBeforeBypass(t *testing.T) {
	ctx := context.Background()
	snapshot, err := outputguard.New([][]byte{[]byte("synthetic-private-literal")})
	if err != nil {
		t.Fatal(err)
	}
	var warning bytes.Buffer
	provider, err := launchguard.Select(agent.FixedOutputGuard(snapshot), false, &warning)
	if err != nil || warning.Len() != 0 {
		t.Fatal("default selection emitted a bypass warning")
	}
	captured, err := provider(ctx)
	if err != nil || captured != snapshot {
		t.Fatal("default selection replaced the authenticated guard")
	}
	assertGuardMasks(t, captured, []byte("synthetic-private-literal"))
	provider, err = launchguard.Select(agent.FixedOutputGuard(nil), true, &warning)
	if err != nil || warning.String() != launchguard.Warning {
		t.Fatal("explicit bypass omitted its complete fixed warning")
	}
	captured, err = provider(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer, err := outputguard.NewWriter(captured, &output)
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("synthetic-private-literal|\x00\xff")
	if n, err := writer.Write(value); n != len(value) || err != nil || writer.Close() != nil || !bytes.Equal(output.Bytes(), value) {
		t.Fatal("deliberate bypass transformed model bytes")
	}
	if provider, err := launchguard.Select(nil, false, &bytes.Buffer{}); provider != nil || err != nil {
		t.Fatal("missing default provider became an unguarded fallback")
	}
}

type refusedWarning struct{ short bool }

func (w refusedWarning) Write(value []byte) (int, error) {
	if w.short {
		return len(value) - 1, nil
	}
	return 0, errors.New("synthetic private sink diagnostic")
}

func TestOutputFilterBypassRefusesMissingOrFailedWarning(t *testing.T) {
	for _, sink := range []io.Writer{nil, refusedWarning{}, refusedWarning{short: true}} {
		provider, err := launchguard.Select(nil, true, sink)
		if provider != nil || err == nil || strings.Contains(err.Error(), "private sink") {
			t.Fatal("bypass ignored failed warning or exposed sink diagnostics")
		}
	}
}

func TestOutputFilterFlagRefusesOtherCommandsAndBrokerLaunchBeforeUnlock(t *testing.T) {
	old := cliLoadAgentCredentials
	t.Cleanup(func() { cliLoadAgentCredentials = old })
	called := false
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
		called = true
		return nil, errors.New("unexpected credential read")
	}
	for _, args := range [][]string{
		{"--no-output-filter", "ssh"}, {"--no-output-filter", "--interactive"},
		{"--no-output-filter", "owner", "status"}, {"--no-output-filter", "--version"},
		{"--no-output-filter", "--mode", "declarative", "run", "fixture"},
		{"--no-output-filter", "--generate-key", "unused", "run", "fixture"},
	} {
		if code, err := Run(context.Background(), args); code == 0 || err == nil || !strings.Contains(err.Error(), "only available for an explicit full-mode") || called {
			t.Fatal("output-filter flag escaped its startup scope")
		}
	}
	t.Setenv(broker.EnvSession, "synthetic active session")
	if code, err := Run(context.Background(), []string{"--no-output-filter", "run", "fixture"}); code == 0 || err == nil || !strings.Contains(err.Error(), "outside broker sessions") || called {
		t.Fatal("broker launch bypassed trusted terminal admission")
	}
}

func TestPrepareMCPBootstrapOutputRequiresSuccessfulOneTimeSetup(t *testing.T) {
	knownSnapshot, err := outputguard.New([][]byte{[]byte("synthetic-known-literal")})
	if err != nil {
		t.Fatal(err)
	}
	for name, snapshot := range map[string]*outputguard.Snapshot{"nil": nil, "invalid": {}} {
		t.Run(name, func(t *testing.T) {
			provider, setup := agent.PrepareMCPBootstrapOutput(context.Background(), agent.FixedOutputGuard(knownSnapshot), nil)
			if current, err := provider(context.Background()); current != nil || err != outputguard.ErrGuard {
				t.Fatal("bootstrap provider was available before output setup")
			}
			if err := setup(snapshot); err != mcpchannel.ErrSetup {
				t.Fatal("invalid bootstrap snapshot was accepted")
			}
			if err := setup(knownSnapshot); err != mcpchannel.ErrSetup {
				t.Fatal("setup succeeded after a failed attempt")
			}
			if current, err := provider(context.Background()); current != nil || err != outputguard.ErrGuard {
				t.Fatal("provider became ready after refused setup")
			}
		})
	}
	provider, setup := agent.PrepareMCPBootstrapOutput(context.Background(), agent.FixedOutputGuard(&outputguard.Snapshot{}), nil)
	if err := setup(knownSnapshot); err != mcpchannel.ErrSetup {
		t.Fatal("failed output-guard union was accepted")
	}
	if current, err := provider(context.Background()); current != nil || err != outputguard.ErrGuard {
		t.Fatal("provider became ready after failed output-guard union")
	}
}

func TestPrepareMCPBootstrapOutputInstallsUnionAndRejectsRepeatOrChangedKnownGuard(t *testing.T) {
	knownSnapshot, err := outputguard.New([][]byte{[]byte("synthetic-known-literal")})
	if err != nil {
		t.Fatal(err)
	}
	knownChanges := false
	known := func(context.Context) (*outputguard.Snapshot, error) {
		if knownChanges {
			return &outputguard.Snapshot{}, nil
		}
		return knownSnapshot, nil
	}
	provider, setup := agent.PrepareMCPBootstrapOutput(context.Background(), known, nil)
	bootstrapSnapshot, err := outputguard.New([][]byte{[]byte("synthetic-bootstrap-literal")})
	if err != nil {
		t.Fatal(err)
	}
	if err := setup(bootstrapSnapshot); err != nil {
		t.Fatal("valid output setup failed")
	}
	if err := setup(bootstrapSnapshot); err != mcpchannel.ErrSetup {
		t.Fatal("repeated output setup was accepted")
	}
	combined, err := provider(context.Background())
	if err != nil {
		t.Fatal("installed combined output guard was unavailable")
	}
	var masked bytes.Buffer
	writer, err := outputguard.NewWriter(combined, &masked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("synthetic-known-literal synthetic-bootstrap-literal")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if masked.String() != outputguard.Marker+" "+outputguard.Marker {
		t.Fatal("combined output guard dropped a known literal")
	}
	knownChanges = true
	if snapshot, err := provider(context.Background()); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("changed known output guard was accepted")
	}
	missingKnown := func(context.Context) (*outputguard.Snapshot, error) { return nil, outputguard.ErrGuard }
	missingProvider, missingSetup := agent.PrepareMCPBootstrapOutput(context.Background(), missingKnown, nil)
	if err := missingSetup(bootstrapSnapshot); err != mcpchannel.ErrSetup {
		t.Fatal("missing known guard allowed setup")
	}
	if snapshot, err := missingProvider(context.Background()); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("missing known guard provided output filtering")
	}
}

type stubKeeperCredentials struct {
	runner  remote.Runner
	guard   remote.GuardProvider
	targets []string
}

func (s *stubKeeperCredentials) Guard() remote.GuardProvider { return s.guard }

func (s *stubKeeperCredentials) Targets() []string { return s.targets }

func (s *stubKeeperCredentials) Stream() remote.StreamRunner { return nil }

func (s *stubKeeperCredentials) Bridge() *mcpbridge.Runtime { return nil }

func (s *stubKeeperCredentials) PrepareRemoteMCPChannels(ctx context.Context, known remote.GuardProvider, ttl time.Duration) (remote.GuardProvider, string, error) {
	return known, "", nil
}

func (s *stubKeeperCredentials) Manager(ctx context.Context, targets []string, guard remote.GuardProvider, noOutputFilter bool) *remote.Manager {
	return remote.NewGuardedManager(ctx, targets, s.runner, guard)
}

func (s *stubKeeperCredentials) Finish(*int, *error) {}

func (s *stubKeeperCredentials) ApplicationApprovals() ([]vault.Approval, error) { return nil, nil }

// TestFullStartupRoutingKeepsStubCredentialsGuarded is the complementary
// cli-package routing check: it proves the full startup still wires the
// bootstrap output setup and required-guard manager through Run. The
// regression of the same behavior against a real Credentials manager lives
// in the agent package as TestFullStartupRoutesModelOutputThroughRequiredGuard.
func TestFullStartupRoutingKeepsStubCredentialsGuarded(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "guarded", true: "missing"}[missing], func(t *testing.T) {
			oldLoad, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
			t.Cleanup(func() { cliLoadAgentCredentials, cliLaunchRun = oldLoad, oldLaunch })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			snapshot, err := outputguard.New([][]byte{[]byte("synthetic-model-secret"), {0, 255, 'b'}})
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
				guard := agent.FixedOutputGuard(snapshot)
				if missing {
					guard = nil
				}
				return &stubKeeperCredentials{
					runner: func(_ context.Context, _, _ string, stdout, stderr io.Writer) (int, error) {
						calls.Add(1)
						for _, value := range []byte("synthetic-model-secret|\x00\xffb|public\xfe") {
							if _, err := stdout.Write([]byte{value}); err != nil {
								return -1, err
							}
						}
						_, err := stderr.Write([]byte("synthetic-model-secret"))
						return 19, err
					},
					guard:   guard,
					targets: []string{"test"},
				}, nil
			}
			cliLaunchRun = func(ctx context.Context, options launch.Options) (int, error) {
				if options.PrepareOutput == nil {
					t.Fatal("full startup omitted bootstrap output setup")
				}
				setupErr := options.PrepareOutput(outputguardSnapshot(t))
				if (missing && setupErr == nil) || (!missing && setupErr != nil) {
					t.Fatal("bootstrap output setup did not match the expected guard state")
				}
				var started remote.StartOutput
				guardedHandlerCall(t, ctx, options.Handler, "start", remote.StartInput{Target: "test", Command: "synthetic"}, &started)
				var out remote.ReadOutput
				flakediag.WaitFor(t, "guarded keeper job completion", childdiag.DeadlineOf(ctx), func() (string, bool) {
					guardedHandlerCall(t, ctx, options.Handler, "read", remote.ReadInput{JobID: started.JobID}, &out)
					if out.Done {
						return "", true
					}
					if err := ctx.Err(); err != nil {
						t.Fatal("guarded keeper job did not finish")
					}
					return "job still running", false
				})
				if missing {
					if calls.Load() != 0 || out.Error != outputguard.ErrGuard.Error() || len(out.Stdout)+len(out.Stderr) != 0 {
						t.Fatal("missing startup guard executed a model job")
					}
				} else if calls.Load() != 1 || out.ExitCode != 19 || out.Error != "" || !bytes.Equal(out.Stdout, []byte("[REDACTED]|[REDACTED]|public\xfe")) || string(out.Stderr) != outputguard.Marker {
					t.Fatal("full startup captured original model bytes or changed control fields")
				}
				return 0, nil
			}
			if code, err := Run(ctx, []string{"run", "synthetic-harness"}); code != 0 || err != nil {
				t.Fatal("guarded full-mode startup failed")
			}
		})
	}
}

func TestMCPBootstrapOutputSetupRefusesRuntimeAfterKeeperAdmission(t *testing.T) {
	runtime := bridgeRuntimeFixture(t, func(context.Context) error { return nil })
	known := outputguardSnapshot(t)
	provider, setup := agent.PrepareMCPBootstrapOutput(context.Background(), agent.FixedOutputGuard(known), runtime)
	data, err := wire.Encode(struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if reply, handled := runtime.Handle(context.Background(), wire.Request{Operation: mcpbridge.OpBindings, Data: data}); !handled || !reply.OK {
		t.Fatal("fixture did not admit its first keeper message")
	}
	if setup(outputguardSnapshot(t)) == nil {
		t.Fatal("setup changed output protection after keeper admission")
	}
	if _, err := provider(context.Background()); err == nil {
		t.Fatal("provider became ready after runtime refused configuration")
	}
}
