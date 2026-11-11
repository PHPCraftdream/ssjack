package main

import (
	"context"
	"errors"
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
	TestOwnerInteractivePTYChild(t)
}

func nativeKeeperProcessAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server, name string, shell *loopbackSSH) {
	t.Helper()
	nativeKeeperCycles(t, ctx, path, password, server, name, shell, []string{"edit", "restart"})
}

func nativeKeeperCycles(t *testing.T, ctx context.Context, path string, password []byte, server, name string, shell *loopbackSSH, cycles []string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_pty_bridge.py"))
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
			if capture.Wait(startup, "Vault secret:") != nil {
				t.Fatal("actual keeper did not request its vault unlock")
			}
			ending := byte('\n')
			if runtime.GOOS == "windows" {
				ending = '\r'
			}
			input := append(append([]byte(nil), password...), ending)
			_, err = terminal.Input.Write(input)
			clear(input)
			if err != nil || capture.Wait(startup, "ACTUAL-KEEPER-HARNESS-READY") != nil {
				t.Fatal("actual keeper did not start its owned harness")
			}
			if cycle == "bypass" && capture.Wait(startup, "WARNING: MCP known-literal output filtering is DISABLED") != nil {
				t.Fatal("trusted bypass launch omitted its terminal warning")
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
					if _, err := terminal.Input.Write([]byte{'r', ending}); err != nil || capture.Wait(scopePhase, "ACTUAL-KEEPER-SSH-SCOPE-REFUSED") != nil {
						t.Fatal("actual keeper did not refuse the changed human SSH scope")
					}
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
					if _, err := terminal.Input.Write([]byte{'r', ending}); err != nil || capture.Wait(scopePhase, "ACTUAL-KEEPER-SSH-SCOPE-REFUSED") != nil {
						t.Fatal("actual keeper did not refuse the changed human SSH scope")
					}
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
				if capture.Wait(guardPhase, "ACTUAL-KEEPER-MCP-GUARD-READY") != nil {
					t.Fatal("actual keeper did not guard its initial MCP job")
				}
				if _, err := terminal.Input.Write([]byte{'g', ending}); err != nil || capture.Wait(guardPhase, "ACTUAL-KEEPER-MCP-GUARD-REFRESHED") != nil {
					t.Fatal("actual keeper did not refresh known literals after helper edits")
				}
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
			if _, err := terminal.Input.Write([]byte{'q', ending}); err != nil || terminal.Wait(shutdown) != nil {
				t.Fatal("actual keeper did not join graceful harness and owner shutdown")
			}
			if capture.Wait(shutdown, "ACTUAL-KEEPER-HARNESS-STOPPED") != nil {
				t.Fatal("harness shutdown acknowledgement was lost")
			}
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
			digest, digestErr := credentialCipherDigest(path)
			if err != nil || len(metadata.Servers) != 1 || metadata.Servers[0].ID != server || metadata.Servers[0].Address != shell.address() || status.Err != nil || status.Database.Err != nil || status.Database.Pending || status.Database.Revision != status.Database.SavedRevision || digestErr != nil || digest == ([32]byte{}) {
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
