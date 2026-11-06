package application

import (
	"context"
	"encoding/json"
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

func fixtureManagerWithGuard(t *testing.T, ctx context.Context, guard remote.GuardProvider) *Manager {
	t.Helper()
	t.Setenv("SSJACK_APPLICATION_TEST_HELPER", "1")
	for _, name := range []string{broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, broker.EnvFile, apptransport.EnvToken, apptransport.EnvEndpoint, apptransport.EnvPin} {
		t.Setenv(name, "stale")
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(ctx, &Options{Guard: guard, Directory: t.TempDir(), Command: []string{program, "-test.run=^TestApplicationProcess$", "--"}, Profile: "host.profile", Runner: func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil }})
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
	applicationCall(t, ctx, manager, "app_start", Input{Application: Name, Arguments: []string{"inspect", "synthetic-app-credential"}}, &started)
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
	applicationCall(t, ctx, manager, "app_start", Input{Application: Name, Arguments: []string{"inspect", "synthetic-app-credential"}}, &started)
	out := readApplication(t, ctx, manager, started.JobID)
	if out.ExitCode != 7 || out.Error != "" || strings.Contains(string(out.Stdout), "synthetic-app-credential") || !strings.Contains(string(out.Stdout), outputguard.Marker) || string(out.Stderr) != "***" {
		t.Fatal("application model output bypassed known-value or bootstrap masking")
	}
}

func TestApplicationMissingGuardRefusesBeforeProcessEffects(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSJACK_APPLICATION_TEST_HELPER", "1")
	manager, err := New(context.Background(), &Options{Directory: t.TempDir(), Command: []string{program, "-test.run=^TestApplicationProcess$", "--"}, Profile: "fixed", Runner: func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var started remote.StartOutput
	applicationCall(t, ctx, manager, "app_start", Input{Application: Name, Arguments: []string{"inspect"}}, &started)
	out := readApplication(t, ctx, manager, started.JobID)
	if out.Error != outputguard.ErrGuard.Error() || out.ExitCode != -1 || len(out.Stdout)+len(out.Stderr) != 0 {
		t.Fatal("missing application guard reached process output or exposed diagnostics")
	}
}
