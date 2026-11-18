package ownertest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/credential"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/sshfixture"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotationtest"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
)

func TestNativeKeeperProcessChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_KEEPER_CHILD") != "1" {
		t.Skip("actual native keeper child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Fatal("keeper did not receive real terminal handles")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), state)
	ownerInteractivePTYChild(t)
}

func nativeKeeperProcessAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server, name string, shell *sshfixture.LoopbackSSH) {
	t.Helper()
	nativeKeeperCycles(t, ctx, path, password, server, name, shell, []string{"edit", "restart"})
}

func nativeKeeperCycles(t *testing.T, ctx context.Context, path string, password []byte, server, name string, shell *sshfixture.LoopbackSSH, cycles []string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cycle := range cycles {
		if !t.Run(cycle, func(t *testing.T) {
			serviceBudget := nativeKeeperServiceBudget
			if cycle == "restart" {
				serviceBudget = 6 * time.Minute
			}
			service, stopService := nativeAcceptanceRoot(t, ctx, serviceBudget)
			defer stopService()
			startup, stopStartup := nativeOperationPhase(t, service, 2*time.Minute)
			defer stopStartup()
			environment := make([]string, 0)
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
					environment = append(environment, entry)
				}
			}
			environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_KEEPER_CHILD=1", "SSJACK_OWNER_TUI_CHILD=1", "SSJACK_OWNER_TUI_CHILD_SECONDS=600")
			arguments := []string{"-test.run=^TestNativeKeeperProcessChild$", "--", "--vault", path, "--server", name, "--account", "main"}
			if cycle == "bypass" {
				arguments = append(arguments, "--no-output-filter")
				environment = append(environment, "SSJACK_OWNER_GUARD_BYPASS_CHILD=1")
			}
			arguments = append(arguments, "run", executable, "-test.run=^TestNativeKeeperHarnessChild$")
			terminal, err := ownerterminal.Start(service, ownerterminal.Command{Executable: executable, UnixBridge: bridge,
				Directory: t.TempDir(), Environment: environment, Args: arguments})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			tail := newOwnerChildTail()
			terminal.Output = teeOwnerChildOutput(terminal.Output, tail)
			ownerChildTerminal(t, "keeper cycle "+cycle, executable, terminal, tail, started)
			capture := ownerterminal.CaptureOutput(terminal.Output)
			defer func() {
				cleanup, stop := nativePhaseCleanup(t)
				defer stop()
				if err := terminal.Close(cleanup); err != nil {
					t.Error("keeper terminal did not close cleanly")
				}
				if capture.Join(cleanup) != nil {
					t.Error("keeper terminal output did not join")
				}
				if capture.Contains(password) || capture.Contains([]byte("synthetic native helper credential")) || capture.Contains([]byte(nativeGuardAddedCredential)) {
					t.Error("actual keeper disclosed private input")
				}
				capture.Clear()
			}()
			captureWaitDiag(t, startup, capture, "Vault secret:", "actual keeper did not request its vault unlock")
			ending := byte('\n')
			if runtime.GOOS == "windows" {
				ending = '\r'
			}
			input := append(append([]byte(nil), password...), ending)
			_, err = terminal.Input.Write(input)
			clear(input)
			if err != nil {
				t.Fatal("actual keeper unlock input failed")
			}
			captureWaitDiag(t, startup, capture, "ACTUAL-KEEPER-HARNESS-READY", "actual keeper did not start its owned harness")
			if cycle == "bypass" {
				captureWaitDiag(t, startup, capture, "WARNING: MCP known-literal output filtering is DISABLED", "trusted bypass launch omitted its terminal warning")
			}
			stopStartup()
			probePhase, stopProbe := nativeOperationPhase(t, service, 30*time.Second)
			probe, err := ownerlocal.Dial(probePhase, path)
			stopProbe()
			if err != nil {
				t.Fatal("actual keeper did not hold the native database endpoint")
			}
			if err := probe.Close(); err != nil {
				t.Fatal(err)
			}
			observerPhase, stopObserverPhase := nativeOperationPhase(t, service, 2*time.Minute)
			observer, err := ownercontrol.Open(service, path, password)
			if err != nil || service.Err() != nil || observerPhase.Err() != nil {
				if observer != nil {
					observer.Detach()
				}
				stopObserverPhase()
				t.Fatal("independent observer could not authenticate within its service budget")
			}
			stopObserverPhase()
			defer observer.Detach()
			if cycle == "edit" {
				commandPhase, stopCommand := nativeOperationPhase(t, service, 2*time.Minute)
				nativeOwnerCommandAcceptance(t, commandPhase, path, password, server, "keeper-added", observer)
				stopCommand()
				interactivePhase, stopInteractive := nativeOperationPhase(t, service, 2*time.Minute)
				t.Run("native-interactive-helper", func(t *testing.T) {
					nativeInteractiveAcceptance(t, interactivePhase, path, password, server, observer)
				})
				stopInteractive()
				humanPhase, stopHuman := nativeOperationPhase(t, service, 2*time.Minute)
				if !t.Run("native-human-ssh", func(t *testing.T) {
					nativeHumanSSHAcceptance(t, humanPhase, path, password, server, observer, shell)
				}) {
					stopHuman()
					return
				}
				stopHuman()
				scopePhase, stopScope := nativeOperationPhase(t, service, time.Minute)
				nativeKeeperRestoreHumanScope(t, scopePhase, path, server, observer, shell, func() {
					if _, err := terminal.Input.Write([]byte{'r', ending}); err != nil {
						t.Fatal("actual keeper scope-refusal input failed")
					}
					captureWaitDiag(t, scopePhase, capture, "ACTUAL-KEEPER-SSH-SCOPE-REFUSED", "actual keeper did not refuse the changed human SSH scope")
				})
				stopScope()
			} else if cycle == "restart" {
				metadata, err := observer.Backend().Metadata()
				found := false
				for _, entry := range metadata.Servers {
					if entry.ID == server {
						for _, account := range entry.Accounts {
							found = found || account.Name == "keeper-added"
						}
					}
				}
				if err != nil || !found {
					t.Fatal("restarted actual keeper lost the confirmed helper account")
				}
			} else {
				humanPhase, stopHuman := nativeOperationPhase(t, service, 2*time.Minute)
				if !t.Run("native-human-ssh", func(t *testing.T) {
					nativeHumanSSHAcceptance(t, humanPhase, path, password, server, observer, shell)
				}) {
					stopHuman()
					return
				}
				stopHuman()
				scopePhase, stopScope := nativeOperationPhase(t, service, time.Minute)
				nativeKeeperRestoreHumanScope(t, scopePhase, path, server, observer, shell, func() {
					if _, err := terminal.Input.Write([]byte{'r', ending}); err != nil {
						t.Fatal("actual keeper scope-refusal input failed")
					}
					captureWaitDiag(t, scopePhase, capture, "ACTUAL-KEEPER-SSH-SCOPE-REFUSED", "actual keeper did not refuse the changed human SSH scope")
				})
				stopScope()
			}
			observerClose, stopObserverClose := nativeOperationPhase(t, service, 30*time.Second)
			if err := observer.Close(observerClose); err != nil {
				stopObserverClose()
				t.Fatal(err)
			}
			stopObserverClose()
			guardPhase, stopGuard := nativeOperationPhase(t, service, 30*time.Second)
			if !t.Run("native-mcp-guard", func(t *testing.T) {
				captureWaitDiag(t, guardPhase, capture, "ACTUAL-KEEPER-MCP-GUARD-READY", "actual keeper did not guard its initial MCP job")
				if _, err := terminal.Input.Write([]byte{'g', ending}); err != nil {
					t.Fatal("actual keeper guard refresh input failed")
				}
				captureWaitDiag(t, guardPhase, capture, "ACTUAL-KEEPER-MCP-GUARD-REFRESHED", "actual keeper did not refresh known literals after helper edits")
			}) {
				stopGuard()
				return
			}
			stopGuard()
			probePhase, stopProbe = nativeOperationPhase(t, service, 30*time.Second)
			probe, err = ownerlocal.Dial(probePhase, path)
			stopProbe()
			if err != nil {
				t.Fatal("helper or observer detach released the actual keeper role")
			}
			if err := probe.Close(); err != nil {
				t.Fatal(err)
			}
			shutdown, stopShutdown := nativeOperationPhase(t, service, 30*time.Second)
			if _, err := terminal.Input.Write([]byte{'q', ending}); err != nil {
				t.Fatal("actual keeper shutdown input failed")
			}
			if err := terminal.Wait(shutdown); err != nil {
				t.Fatal("actual keeper did not join graceful harness and owner shutdown")
			}
			captureWaitDiag(t, shutdown, capture, "ACTUAL-KEEPER-HARNESS-STOPPED", "harness shutdown acknowledgement was lost")
			stopShutdown()
			stopService()
			reopenCtx, reopenCancel := nativeOperationPhase(t, ctx, time.Minute)
			defer reopenCancel()
			probe, err = ownerlocal.Dial(reopenCtx, path)
			if err == nil {
				if err := probe.Close(); err != nil {
					t.Fatal("standalone reopen probe did not close")
				}
				t.Fatal("standalone reopen endpoint was not released")
			}
			if !errors.Is(err, ownerlocal.ErrAbsent) {
				if reopenCtx.Err() != nil {
					t.Fatal("standalone reopen phase budget ended")
				}
				t.Fatal("standalone reopen endpoint was not released")
			}
			reopened, err := ownercontrol.Open(reopenCtx, path, password)
			if err != nil {
				if reopenCtx.Err() != nil {
					t.Fatal("standalone reopen phase budget ended")
				}
				t.Fatal("joined keeper shutdown could not reacquire standalone control")
			}
			defer func() {
				cleanup, stop := nativePhaseCleanup(t)
				defer stop()
				if err := reopened.Close(cleanup); err != nil {
					t.Error("standalone control cleanup failed")
				}
			}()
			metadata, err := reopened.Backend().Metadata()
			status := reopened.Backend().Status()
			digest, digestErr := credential.CredentialCipherDigest(path)
			if err != nil || len(metadata.Servers) != 1 || metadata.Servers[0].ID != server || metadata.Servers[0].Address != shell.Address() || status.Err != nil || status.Database.Err != nil || status.Database.Pending || status.Database.Revision != status.Database.SavedRevision || digestErr != nil || digest == ([32]byte{}) {
				t.Fatal("restarted fixture did not retain the explicitly restored human SSH scope")
			}
			if err := reopened.Close(reopenCtx); err != nil {
				if reopenCtx.Err() != nil {
					t.Fatal("standalone reopen phase budget ended")
				}
				t.Fatal("standalone control close failed")
			}
		}) {
			return
		}
	}
}

func nativeKeeperRestoreHumanScope(t *testing.T, ctx context.Context, path, server string, observer *ownercontrol.Control, shell *sshfixture.LoopbackSSH, refuse func()) {
	t.Helper()
	metadata, err := observer.Backend().Metadata()
	status := observer.Backend().Status()
	if err != nil || len(metadata.Servers) != 1 || metadata.Servers[0].ID != server || metadata.Servers[0].Address != "127.0.0.1:3" || status.Err != nil || status.Database.Err != nil || status.Database.Pending || status.Database.Revision != status.Database.SavedRevision {
		t.Fatal("human SSH scope change was not saved as the exact fixture endpoint")
	}
	connections := shell.AcceptedConnections()
	refuse()
	if shell.AcceptedConnections() != connections {
		t.Fatal("refused changed-scope MCP operation opened an SSH connection")
	}
	probe, err := ownerlocal.Dial(ctx, path)
	if err != nil {
		t.Fatal("changed-scope refusal released the actual keeper role")
	}
	if err := probe.Close(); err != nil {
		t.Fatal("actual keeper role probe did not close")
	}
	nativeServerAddress(t, ctx, observer, server, shell.Address())
	metadata, err = observer.Backend().Metadata()
	status = observer.Backend().Status()
	digest, digestErr := credential.CredentialCipherDigest(path)
	if err != nil || len(metadata.Servers) != 1 || metadata.Servers[0].ID != server || metadata.Servers[0].Address != shell.Address() || status.Err != nil || status.Database.Err != nil || status.Database.Pending || status.Database.Revision != status.Database.SavedRevision || digestErr != nil || digest == ([32]byte{}) {
		t.Fatal("explicit human SSH scope restoration did not produce a healthy saved fixture")
	}
}

func nativeServerAddress(t *testing.T, ctx context.Context, control *ownercontrol.Control, server, address string) {
	t.Helper()
	status := control.Backend().Status()
	if status.Err != nil || status.Database.Err != nil {
		t.Fatal("observer could not read the explicit fixture revision")
	}
	scoper, ok := control.Backend().(interface {
		AtRevision(uint64) ownertui.Backend
	})
	if !ok {
		t.Fatal("observer lost revision-scoped admission")
	}
	backend, ok := scoper.AtRevision(status.Database.Revision).(interface {
		ApplyDirectory(ownerpacket.DirectoryChange) error
	})
	if !ok {
		t.Fatal("observer lost typed directory admission")
	}
	if err := backend.ApplyDirectory(ownerpacket.DirectoryChange{Action: "edit-server", ServerID: server, Fields: [][]byte{[]byte(address), nil}}); err != nil {
		t.Fatal(err)
	}
	if err := control.Backend().Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func nativeHumanSSHAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server string, observer *ownercontrol.Control, loopback *sshfixture.LoopbackSSH) {
	t.Helper()
	nativeServerAddress(t, ctx, observer, server, loopback.Address())
	metadata, err := observer.Backend().Metadata()
	if err != nil {
		t.Fatal(err)
	}
	name, human := "", 0
	for _, entry := range metadata.Servers {
		if entry.ID == server {
			name = entry.Name
		}
		for _, account := range entry.Accounts {
			if account.Usage == "" || account.Usage == "human" || account.Usage == "both" {
				human++
			}
		}
	}
	if name == "" || human != 1 {
		t.Fatal("human SSH server metadata is missing")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	connections := loopback.AcceptedConnections()
	authentications := len(loopback.Authentications())
	exits := len(loopback.ExitStatuses())
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_NATIVE_TUI_CHILD=1", "SSJACK_OWNER_TUI_CHILD=1")
	terminal, err := ownerterminal.Start(ctx, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
		Args: []string{"-test.run=^TestNativeInteractiveProcessChild$", "--", "--vault", path, "--interactive"}})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	tail := newOwnerChildTail()
	terminal.Output = teeOwnerChildOutput(terminal.Output, tail)
	ownerChildTerminal(t, "human SSH handoff", executable, terminal, tail, started)
	capture := ownerterminal.CaptureOutput(terminal.Output)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = terminal.Close(cleanup)
		if capture.Join(cleanup) != nil || capture.Contains(password) {
			t.Error("human SSH terminal did not join or exposed the vault unlock")
		}
		capture.Clear()
	}()
	expect := func(text string) {
		captureWaitDiag(t, ctx, capture, text, "native human SSH flow did not reach: "+text)
	}
	send := func(data []byte) {
		if _, err := terminal.Input.Write(data); err != nil {
			t.Fatal("native human SSH input failed")
		}
	}
	expect("Vault secret:")
	ending := byte('\n')
	if runtime.GOOS == "windows" {
		ending = '\r'
	}
	input := append(append([]byte(nil), password...), ending)
	_, err = terminal.Input.Write(input)
	clear(input)
	if err != nil {
		t.Fatal("native human SSH unlock input failed")
	}
	expect("Connect:")
	// Right must not connect; the following Servers screen is the input barrier.
	send([]byte("\x1b[C\x1b[B\r"))
	expect("[Add server]")
	if loopback.AcceptedConnections() != connections {
		t.Fatal("picker connected before an explicit Enter decision")
	}
	send([]byte("\x1b[D\r"))
	expect("SYNTHETIC-SSH-READY user=second")
	if capture.Contains([]byte(sshfixture.ConnectPassword)) {
		t.Fatal("SSH authentication was disclosed before deliberate human output")
	}
	t.Run("legacy-writer-refusal", func(t *testing.T) {
		nativeWriterRefusal(t, ctx, path, password, name, loopback)
	})
	// Later owner edits must not replace or terminate the captured live shell.
	nativeServerAddress(t, ctx, observer, server, "127.0.0.1:3")
	input = append([]byte(sshfixture.ConnectPassword), '\r')
	send(input)
	clear(input)
	expect("ECHO:" + sshfixture.ConnectPassword)
	send([]byte("exit\r"))
	// Fresh metadata replaces the transient exit message after the address edit.
	expect("The list changed; choose an entry again.")
	send([]byte{3})
	if terminal.Wait(ctx) != nil {
		t.Fatal("human shell handoff did not restore and close the picker")
	}
	statuses := loopback.ExitStatuses()
	if len(statuses) != exits+1 || statuses[len(statuses)-1] != 0 {
		t.Fatal("loopback SSH did not send exactly one zero exit status")
	}
	accepted := loopback.Authentications()
	if loopback.AcceptedConnections() != connections+1 || len(accepted) != authentications+1 || accepted[len(accepted)-1] != "second|password" {
		t.Fatal("native handoff used the wrong account or opened extra SSH connections")
	}
}

// ownerInteractivePTYChild mirrors the owneracceptance interactive PTY child:
// the helper contents were copied verbatim (same environment switches, same
// cli.Run invocation) and renamed to a local helper instead of a second Test.
func ownerInteractivePTYChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_TUI_CHILD") != "1" {
		t.Skip("synthetic terminal child only")
	}
	var args []string
	for i, argument := range os.Args {
		if argument == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	// The import terminal flow pays several production-KDF passes; it asks for a
	// longer bound explicitly, every other caller keeps one minute.
	limit := time.Minute
	if seconds, err := strconv.Atoi(os.Getenv("SSJACK_OWNER_TUI_CHILD_SECONDS")); err == nil && seconds > 0 && seconds <= 600 {
		limit = time.Duration(seconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	code, err := cli.Run(ctx, args)
	if code != 0 || err != nil {
		reason := "other"
		if err != nil {
			switch err.Error() {
			case "owner terminal editor stopped unexpectedly":
				reason = "terminal"
			case "owner editor stopped with unsaved or unresolved changes; reopen the encrypted database and inspect pending recovery":
				reason = "save"
			case "cannot unlock owner database; directory payload schema v2 is required":
				reason = "unlock"
			}
		}
		t.Fatalf("synthetic interactive child failed: code=%d context-ended=%t reason=%s", code, ctx.Err() != nil, reason)
	}
}

func TestVaultOwnerRotationRecoveryFullProfile(t *testing.T) {
	// The rotation rig re-execs this test binary for TestNativeKeeperProcessChild
	// (ownertest-only) and resolves its PTY bridge two parents above the test
	// cwd; scope the cwd to cmd/ssjack and restore it at cleanup.
	t.Chdir(filepath.Join("..", ".."))
	ownerrotationtest.Accept(t)
}
func TestRotationComposedProcessChild(t *testing.T) {
	ownerrotationtest.Child(t, cli.Run)
}
