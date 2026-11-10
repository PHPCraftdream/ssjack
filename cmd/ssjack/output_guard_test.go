package main

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

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

func TestPrepareMCPBootstrapOutputRequiresSuccessfulOneTimeSetup(t *testing.T) {
	knownSnapshot, err := outputguard.New([][]byte{[]byte("synthetic-known-literal")})
	if err != nil {
		t.Fatal(err)
	}
	for name, snapshot := range map[string]*outputguard.Snapshot{"nil": nil, "invalid": {}} {
		t.Run(name, func(t *testing.T) {
			provider, setup := prepareMCPBootstrapOutput(context.Background(), fixedOutputGuard(knownSnapshot), nil)
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
	provider, setup := prepareMCPBootstrapOutput(context.Background(), fixedOutputGuard(&outputguard.Snapshot{}), nil)
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
	provider, setup := prepareMCPBootstrapOutput(context.Background(), known, nil)
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
	missingProvider, missingSetup := prepareMCPBootstrapOutput(context.Background(), missingKnown, nil)
	if err := missingSetup(bootstrapSnapshot); err != mcpchannel.ErrSetup {
		t.Fatal("missing known guard allowed setup")
	}
	if snapshot, err := missingProvider(context.Background()); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("missing known guard provided output filtering")
	}
}

func TestFullStartupRoutesModelOutputThroughRequiredGuard(t *testing.T) {
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
			cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
				credentials := &agentCredentials{targets: []string{"test"}, guard: fixedOutputGuard(snapshot), runner: func(_ context.Context, _, _ string, stdout, stderr io.Writer) (int, error) {
					calls.Add(1)
					for _, value := range []byte("synthetic-model-secret|\x00\xffb|public\xfe") {
						if _, err := stdout.Write([]byte{value}); err != nil {
							return -1, err
						}
					}
					_, err := stderr.Write([]byte("synthetic-model-secret"))
					return 19, err
				}}
				if missing {
					credentials.guard = nil
				}
				return credentials, nil
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
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				var out remote.ReadOutput
				for {
					guardedHandlerCall(t, ctx, options.Handler, "read", remote.ReadInput{JobID: started.JobID}, &out)
					if out.Done {
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("guarded keeper job did not finish")
					case <-ticker.C:
					}
				}
				if missing {
					if calls.Load() != 0 || out.Error != outputguard.ErrGuard.Error() || len(out.Stdout)+len(out.Stderr) != 0 {
						t.Fatal("missing startup guard executed a model job")
					}
				} else if calls.Load() != 1 || out.ExitCode != 19 || out.Error != "" || !bytes.Equal(out.Stdout, []byte("[REDACTED]|[REDACTED]|public\xfe")) || string(out.Stderr) != outputguard.Marker {
					t.Fatal("full startup captured original model bytes or changed control fields")
				}
				return 0, nil
			}
			if code, err := run(ctx, []string{"run", "synthetic-harness"}); code != 0 || err != nil {
				t.Fatal("guarded full-mode startup failed")
			}
		})
	}
}

func TestMCPBootstrapOutputSetupRefusesRuntimeAfterKeeperAdmission(t *testing.T) {
	runtime := bridgeRuntimeFixture(t, func(context.Context) error { return nil })
	known := outputguardSnapshot(t)
	provider, setup := prepareMCPBootstrapOutput(context.Background(), fixedOutputGuard(known), runtime)
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
