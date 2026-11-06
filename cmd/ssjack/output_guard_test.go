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
