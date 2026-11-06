package application

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

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
