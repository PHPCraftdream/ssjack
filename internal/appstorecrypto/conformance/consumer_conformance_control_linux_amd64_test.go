//go:build linux && amd64

package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/connectedkit"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/syntheticconsumer"
)

// The kit's assertions are only meaningful if they can fail. These controls
// run the kit's own helpers against the synthetic consumer with and without a
// deliberate defect, over the real listener with in-memory adapters (no root,
// no SSH), and require the kit to report the defect.

const consumerProcessEnv = "SYNTHETIC_CONSUMER_PROCESS"

// TestSyntheticConsumerProcess lets the test binary act as the synthetic
// consumer process: the controls re-execute it with the consumer arguments
// after "--". Without that environment it does nothing.
func TestSyntheticConsumerProcess(t *testing.T) {
	if os.Getenv(consumerProcessEnv) != "1" {
		t.Skip("consumer process entry for the negative controls only")
	}
	for index, value := range os.Args {
		if value == "--" {
			os.Exit(syntheticconsumer.Run(os.Args[index+1:], os.Stdout))
		}
	}
	t.Fatal("missing consumer arguments")
}

// consumerRecorder implements consumerT and records failures instead of
// failing its test; Fatal ends only the goroutine that runs the kit body.
type consumerRecorder struct {
	dir      string
	mu       sync.Mutex
	failures []string
}

func (r *consumerRecorder) Helper() {}

func (r *consumerRecorder) record(message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, message)
}

func (r *consumerRecorder) Fatal(args ...any) {
	r.record(fmt.Sprint(args...))
	runtime.Goexit()
}

func (r *consumerRecorder) Fatalf(format string, args ...any) {
	r.record(fmt.Sprintf(format, args...))
	runtime.Goexit()
}

func (r *consumerRecorder) Error(args ...any) { r.record(fmt.Sprint(args...)) }

func (r *consumerRecorder) TempDir() string { return r.dir }

func captureConsumerKit(t *testing.T, body func(consumerT)) []string {
	t.Helper()
	recorder := &consumerRecorder{dir: t.TempDir()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		body(recorder)
	}()
	<-done
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]string(nil), recorder.failures...)
}

type controlHydrator struct{ calls atomic.Int32 }

func (c *controlHydrator) Hydrate(context.Context, string, string, []byte) appstorecrypto.DeliveryOutcome {
	c.calls.Add(1)
	return appstorecrypto.DeliveryOutcome{Status: appstorecrypto.DeliveryReceived}
}

type controlReverse struct{ calls atomic.Int32 }

func (c *controlReverse) ReverseCopy(context.Context, string, string) appstorecrypto.ReverseTextOutcome {
	c.calls.Add(1)
	return appstorecrypto.ReverseTextOutcome{Status: appstorecrypto.DeliveryReceived, Text: []byte("reference-only copy\n")}
}

func controlRunner(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
	return 0, nil
}

func controlHydrateServer(t *testing.T, adapter apptransport.TextHydrator) apptransport.Bootstrap {
	t.Helper()
	server, err := apptransport.ListenWithTextAdapter(context.Background(), consumerProfile, controlRunner, adapter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return server.Bootstrap()
}

func controlReverseServer(t *testing.T, adapter apptransport.TextReverseCopier) apptransport.Bootstrap {
	t.Helper()
	server, err := apptransport.ListenWithReverseTextAdapter(context.Background(), consumerProfile, controlRunner, adapter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return server.Bootstrap()
}

func TestConsumerKitNegativeControls(t *testing.T) {
	cases := []struct {
		name     string
		fault    string
		scenario string
		want     string // empty: the kit must pass
	}{
		{"correct consumer deploy", "", "deploy", ""},
		{"correct consumer existing output", "", "existing", ""},
		{"leaked value", "leak=" + connectedkit.PairShortSecret, "deploy", "consumer output disclosed private data"},
		{"existing output overwritten and reported received", "overwrite-output", "existing", "consumer completion mismatch"},
		{"existing output overwritten and reported unknown", "clobber-output", "existing", "existing output was modified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"-test.run=^TestSyntheticConsumerProcess$", "--", "--consumer", "synthetic"}
			if tc.fault != "" {
				args = append(args, "--fault", tc.fault)
			}
			encoded, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(consumerCommandEnv, executable)
			t.Setenv(consumerArgsEnv, string(encoded))
			t.Setenv(consumerEnvEnv, `{"`+consumerProcessEnv+`":"1"}`)
			var failures []string
			switch tc.scenario {
			case "deploy":
				hydrator := &controlHydrator{}
				bootstrap := controlHydrateServer(t, hydrator)
				failures = captureConsumerKit(t, func(k consumerT) {
					cli := newConsumerCLI(k, "setting=placeholder\n")
					cli.deploy(k, &bootstrap, "received", true, "--file", "/approved/file", "--template", cli.templatePath, "--profile", consumerProfile)
				})
			case "existing":
				reverse := &controlReverse{}
				bootstrap := controlReverseServer(t, reverse)
				failures = captureConsumerKit(t, func(k consumerT) {
					cli := newConsumerCLI(k, "unused\n")
					if err := os.WriteFile(cli.backupPath, []byte("existing copy\n"), 0o600); err != nil {
						k.Fatal(err)
					}
					cli.backupExisting(k, &bootstrap, func() int { return int(reverse.calls.Load()) }, "--file", "/approved/file", "--output", cli.backupPath, "--profile", consumerProfile)
				})
			default:
				t.Fatalf("unknown scenario %q", tc.scenario)
			}
			if tc.want == "" {
				if len(failures) != 0 {
					t.Fatalf("the kit failed a correct consumer: %q", failures)
				}
				return
			}
			if len(failures) == 0 {
				t.Fatal("the kit accepted a deliberately broken consumer")
			}
			if !strings.Contains(failures[0], tc.want) {
				t.Fatalf("the kit failed for the wrong reason: %q, want %q", failures[0], tc.want)
			}
		})
	}
}
