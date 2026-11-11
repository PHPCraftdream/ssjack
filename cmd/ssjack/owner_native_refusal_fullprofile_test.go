package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const nativeTestCleanupReserve = time.Minute
const nativeKeeperServiceBudget = 10 * time.Minute

// nativeDeadline caps a finite root by its parent and leaves the test cleanup reserve.
func nativeDeadline(now time.Time, budget, reserve time.Duration, parentDeadline time.Time, hasParent bool, testDeadline time.Time, hasTest bool) (time.Time, error) {
	if budget <= 0 || reserve < 0 {
		return time.Time{}, errors.New("invalid native acceptance budget")
	}
	deadline := now.Add(budget)
	if hasParent && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	if hasTest {
		available := testDeadline.Add(-reserve)
		if available.Before(deadline) {
			deadline = available
		}
	}
	if !deadline.After(now) {
		return time.Time{}, errors.New("native acceptance deadline leaves no time before cleanup reserve")
	}
	return deadline, nil
}

func nativePhaseDeadline(now time.Time, budget time.Duration, parentDeadline time.Time, hasParent bool) (time.Time, error) {
	if budget <= 0 {
		return time.Time{}, errors.New("invalid native operation budget")
	}
	deadline := now.Add(budget)
	if hasParent && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	if !deadline.After(now) {
		return time.Time{}, errors.New("native operation deadline has expired")
	}
	return deadline, nil
}

func nativeAcceptanceRoot(t *testing.T, parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	if parent == nil || parent.Err() != nil {
		t.Fatal("native acceptance root parent is unavailable")
	}
	parentDeadline, hasParent := parent.Deadline()
	testDeadline, hasTest := t.Deadline()
	deadline, err := nativeDeadline(time.Now(), budget, nativeTestCleanupReserve, parentDeadline, hasParent, testDeadline, hasTest)
	if err != nil {
		t.Fatal(err)
	}
	return context.WithDeadline(parent, deadline)
}

func nativeOperationPhase(t *testing.T, parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	if parent == nil || parent.Err() != nil {
		t.Fatal("native acceptance service lifetime ended before its operation phase")
	}
	parentDeadline, hasParent := parent.Deadline()
	deadline, err := nativePhaseDeadline(time.Now(), budget, parentDeadline, hasParent)
	if err != nil {
		t.Fatal(err)
	}
	return context.WithDeadline(parent, deadline)
}

func nativePhaseCleanup(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), nativeTestCleanupReserve)
}

func TestNativeAcceptancePhaseBudgetTopology(t *testing.T) {
	now := time.Date(2026, time.November, 11, 0, 0, 0, 0, time.UTC)
	parentDeadline, testDeadline := now.Add(10*time.Minute), now.Add(11*time.Minute)
	if _, err := nativeDeadline(now, 10*time.Minute, time.Minute, parentDeadline, true, testDeadline, true); err != nil {
		t.Fatalf("finite root with cleanup reserve was refused: %v", err)
	}
	if deadline, err := nativeDeadline(now, 10*time.Minute, time.Minute, parentDeadline, true, testDeadline.Add(-5*time.Minute), true); err != nil || !deadline.Equal(testDeadline.Add(-6*time.Minute)) {
		t.Fatalf("root did not preserve test cleanup reserve under a shorter test deadline: deadline=%v err=%v", deadline, err)
	}
	if _, err := nativeDeadline(now, 10*time.Minute, time.Minute, parentDeadline, true, now.Add(time.Minute), true); err == nil {
		t.Fatal("root accepted a deadline with no time before cleanup reserve")
	}
	phaseStart := now.Add(83*time.Second + 600*time.Millisecond)
	oldEnd := now.Add(2 * time.Minute)
	oldPhase, err := nativePhaseDeadline(phaseStart, time.Minute, oldEnd, true)
	if err != nil || !oldPhase.Equal(oldEnd) || oldPhase.Sub(phaseStart) != 36*time.Second+400*time.Millisecond {
		t.Fatalf("old two-minute root did not cap the phase at 36.4 seconds: deadline=%v err=%v", oldPhase, err)
	}
	freshEnd, err := nativeDeadline(now, nativeKeeperServiceBudget, time.Minute, now.Add(15*time.Minute), true, testDeadline, true)
	if err != nil || !freshEnd.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("fresh ten-minute root deadline was not retained: deadline=%v err=%v", freshEnd, err)
	}
	freshPhase, err := nativePhaseDeadline(phaseStart, time.Minute, freshEnd, true)
	if err != nil || !freshPhase.Equal(phaseStart.Add(time.Minute)) {
		t.Fatalf("fresh ten-minute root did not retain the full phase: %v", err)
	}
}

func TestNativeAcceptancePhaseCancellationTopology(t *testing.T) {
	service, cancelService := context.WithCancel(context.Background())
	defer cancelService()
	first, cancelFirst := nativeOperationPhase(t, service, time.Minute)
	cancelFirst()
	if !errors.Is(first.Err(), context.Canceled) || service.Err() != nil {
		t.Fatal("canceling the first operation phase canceled its service lifetime")
	}
	second, cancelSecond := nativeOperationPhase(t, service, time.Minute)
	defer cancelSecond()
	if second.Err() != nil {
		t.Fatal("fresh operation phase inherited cancellation from the first phase")
	}
	cancelService()
	if !errors.Is(service.Err(), context.Canceled) || !errors.Is(second.Err(), context.Canceled) {
		t.Fatal("service cancellation did not propagate to the fresh operation phase")
	}
}

func nativeKeeperRestoreHumanScope(t *testing.T, ctx context.Context, path, server string, observer *ownercontrol.Control, shell *loopbackSSH, refuse func()) {
	t.Helper()
	metadata, err := observer.Backend().Metadata()
	status := observer.Backend().Status()
	if err != nil || len(metadata.Servers) != 1 || metadata.Servers[0].ID != server || metadata.Servers[0].Address != "127.0.0.1:3" || status.Err != nil || status.Database.Err != nil || status.Database.Pending || status.Database.Revision != status.Database.SavedRevision {
		t.Fatal("human SSH scope change was not saved as the exact fixture endpoint")
	}
	connections := shell.acceptedConnections()
	refuse()
	if shell.acceptedConnections() != connections {
		t.Fatal("refused changed-scope MCP operation opened an SSH connection")
	}
	probe, err := ownerlocal.Dial(ctx, path)
	if err != nil {
		t.Fatal("changed-scope refusal released the actual keeper role")
	}
	if err := probe.Close(); err != nil {
		t.Fatal("actual keeper role probe did not close")
	}
	nativeServerAddress(t, ctx, observer, server, shell.address())
	metadata, err = observer.Backend().Metadata()
	status = observer.Backend().Status()
	digest, digestErr := credentialCipherDigest(path)
	if err != nil || len(metadata.Servers) != 1 || metadata.Servers[0].ID != server || metadata.Servers[0].Address != shell.address() || status.Err != nil || status.Database.Err != nil || status.Database.Pending || status.Database.Revision != status.Database.SavedRevision || digestErr != nil || digest == ([32]byte{}) {
		t.Fatal("explicit human SSH scope restoration did not produce a healthy saved fixture")
	}
}

func TestNativeWriterRefusalChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_NATIVE_REFUSAL_CHILD") != "1" {
		t.Skip("actual native writer refusal child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Fatal("writer refusal child lacks a real terminal")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), state)
	var args []string
	for index, value := range os.Args {
		if value == "--" {
			args = os.Args[index+1:]
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if code, err := run(ctx, args); code != 1 || !errors.Is(err, vault.ErrWriterRole) {
		t.Fatal("actual legacy writer did not refuse at native role admission")
	}
	fmt.Fprintln(os.Stdout, "ACTUAL-LEGACY-WRITER-REFUSED")
}

func nativeWriterRefusal(t *testing.T, parent context.Context, path string, password []byte, name string, server *loopbackSSH) {
	t.Helper()
	ctx, cancel := nativeOperationPhase(t, parent, time.Minute)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	connections := server.acceptedConnections()
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "SSJACK_OWNER_NATIVE_REFUSAL_CHILD=1")
	terminal, err := ownerterminal.Start(ctx, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
		Args: []string{"-test.run=^TestNativeWriterRefusalChild$", "--", "--vault", path, "--server", name, "--account", "key-only", "rotate"}})
	if err != nil {
		t.Fatal(err)
	}
	capture := ownerterminal.CaptureOutput(terminal.Output)
	defer func() {
		cleanup, cancel := nativePhaseCleanup(t)
		defer cancel()
		if err := terminal.Close(cleanup); err != nil {
			t.Error("writer refusal child did not close cleanly")
		}
		if capture.Join(cleanup) != nil || capture.Contains(password) {
			t.Error("writer refusal did not join safely or exposed hidden input")
		}
		capture.Clear()
	}()
	if capture.Wait(ctx, "Vault secret:") != nil {
		t.Fatal("actual legacy writer did not request its unlock")
	}
	ending := byte('\n')
	if runtime.GOOS == "windows" {
		ending = '\r'
	}
	input := append(append([]byte(nil), password...), ending)
	_, err = terminal.Input.Write(input)
	clear(input)
	if err != nil {
		t.Fatal("actual legacy writer unlock input failed")
	}
	if err := terminal.Wait(ctx); err != nil {
		t.Fatal("actual legacy writer did not complete its process")
	}
	if capture.Wait(ctx, "ACTUAL-LEGACY-WRITER-REFUSED") != nil {
		t.Fatal("actual legacy writer did not report its refusal")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || server.acceptedConnections() != connections {
		t.Fatal("refused legacy writer changed ciphertext or reached the SSH server")
	}
}
