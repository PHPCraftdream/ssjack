package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const fixtureName = "synthetic"

// fixtureApp registers the test binary itself as a synthetic application.
func fixtureApp(t *testing.T, name string) App {
	t.Helper()
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	return App{
		Name:          name,
		Directory:     directory,
		Workdir:       directory,
		Executable:    program,
		Args:          []string{"-test.run=^TestApplicationProcess$", "--"},
		Observational: []string{"status", "inspect"},
		Refused:       []string{"serve", "mcp-serve"},
	}
}

func fixtureManagerWithGuard(t *testing.T, ctx context.Context, guard remote.GuardProvider) *Manager {
	t.Helper()
	return fixtureManagerFor(t, ctx, guard, fixtureApp(t, fixtureName))
}

func fixtureManagerFor(t *testing.T, ctx context.Context, guard remote.GuardProvider, apps ...App) *Manager {
	t.Helper()
	t.Setenv("SSJACK_APPLICATION_TEST_HELPER", "1")
	for _, name := range []string{broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, broker.EnvFile, apptransport.EnvToken, apptransport.EnvEndpoint, apptransport.EnvPin} {
		t.Setenv(name, "stale")
	}
	manager, err := New(ctx, &Options{Guard: guard, Apps: apps, Profile: "host.profile", Runner: func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	return manager
}

func TestExplicitLiteralBypassPreservesApplicationBootstrapMasking(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	empty, err := outputguard.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	manager := fixtureManagerWithGuard(t, ctx, func(context.Context) (*outputguard.Snapshot, error) { return empty, nil })
	var started remote.StartOutput
	applicationCall(t, ctx, manager, "app_start", Input{Application: fixtureName, Arguments: []string{"inspect", "synthetic-app-credential"}}, &started)
	out := readApplication(t, ctx, manager, started.JobID)
	var body struct{ Token string }
	if json.Unmarshal(out.Stdout, &body) != nil || body.Token != "***" || out.ExitCode != 7 || out.Error != "" || !strings.Contains(string(out.Stdout), "synthetic-app-credential") || string(out.Stderr) != "***" {
		t.Fatal("literal bypass disabled bootstrap masking or transformed permitted model bytes")
	}
}

func applicationFixtureGuard(t *testing.T) remote.GuardProvider {
	t.Helper()
	snapshot, err := outputguard.New([][]byte{[]byte("synthetic-app-credential")})
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context) (*outputguard.Snapshot, error) { return snapshot, nil }
}

func TestApplicationCapturesKnownValuesOnlyThroughGuard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	manager := fixtureManager(t, ctx)
	var started remote.StartOutput
	applicationCall(t, ctx, manager, "app_start", Input{Application: fixtureName, Arguments: []string{"inspect", "synthetic-app-credential"}}, &started)
	out := readApplication(t, ctx, manager, started.JobID)
	if out.ExitCode != 7 || out.Error != "" || strings.Contains(string(out.Stdout), "synthetic-app-credential") || !strings.Contains(string(out.Stdout), outputguard.Marker) || string(out.Stderr) != "***" {
		t.Fatal("application model output bypassed known-value or bootstrap masking")
	}
}

func TestApplicationMissingGuardRefusesBeforeProcessEffects(t *testing.T) {
	t.Setenv("SSJACK_APPLICATION_TEST_HELPER", "1")
	manager, err := New(context.Background(), &Options{Apps: []App{fixtureApp(t, fixtureName)}, Profile: "fixed", Runner: func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var started remote.StartOutput
	applicationCall(t, ctx, manager, "app_start", Input{Application: fixtureName, Arguments: []string{"inspect"}}, &started)
	out := readApplication(t, ctx, manager, started.JobID)
	if out.Error != outputguard.ErrGuard.Error() || out.ExitCode != -1 || len(out.Stdout)+len(out.Stderr) != 0 {
		t.Fatal("missing application guard reached process output or exposed diagnostics")
	}
}

func TestSecretWriterEveryBoundary(t *testing.T) {
	secret := strings.Repeat("0123456789abcdef", 4)
	input := []byte("prefix\x00" + secret + secret + "suffix\xff")
	want := []byte("prefix\x00******suffix\xff")
	for split := 0; split <= len(input); split++ {
		var output bytes.Buffer
		w := newSecretWriter(&output, secret)
		for _, part := range [][]byte{input[:split], input[split:]} {
			if n, err := w.Write(part); n != len(part) || err != nil {
				t.Fatalf("split %d: write %d, %v", split, n, err)
			}
			if len(w.pending) >= len(secret) {
				t.Fatal("retained more than one incomplete match")
			}
		}
		if err := w.flush(); err != nil || !bytes.Equal(output.Bytes(), want) {
			t.Fatalf("split %d: output mismatch, %v", split, err)
		}
		if err := w.flush(); err != nil || !bytes.Equal(output.Bytes(), want) {
			t.Fatal("flush was not idempotent")
		}
		if _, err := w.Write([]byte(secret)); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("accepted output after final flush")
		}
	}
}

func TestSecretWriterBytewiseAndUnmatched(t *testing.T) {
	secret := strings.Repeat("abc123", 10)
	input := []byte(strings.Repeat("other\x00", 100) + secret + secret[:len(secret)-1])
	var output bytes.Buffer
	w := newSecretWriter(&output, secret)
	for _, value := range input {
		if _, err := w.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.flush(); err != nil {
		t.Fatal(err)
	}
	want := bytes.ReplaceAll(input, []byte(secret), []byte("***"))
	if !bytes.Equal(output.Bytes(), want) {
		t.Fatal("bytewise or incomplete final match changed unrelated bytes")
	}
}

type outputFunc func([]byte) (int, error)

func (f outputFunc) Write(data []byte) (int, error) { return f(data) }

func TestSecretWriterOutputErrors(t *testing.T) {
	failure := errors.New("sink failed")
	for _, sink := range []io.Writer{
		outputFunc(func([]byte) (int, error) { return 0, failure }),
		outputFunc(func([]byte) (int, error) { return 0, nil }),
	} {
		w := newSecretWriter(sink, "secret")
		if _, err := w.Write([]byte("long unrelated output")); err == nil {
			t.Fatal("sink failure was lost")
		}
		if err := w.flush(); err == nil {
			t.Fatal("flush lost the sink failure")
		}
	}
	w := newSecretWriter(outputFunc(func([]byte) (int, error) { return 0, failure }), "secret")
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.flush(); !errors.Is(err, failure) {
		t.Fatal("trailing sink failure was lost")
	}
}
