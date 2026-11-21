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
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotationtest"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const (
	nativeKeeperStdinFailure         nativeChildFailure = "keeper-stdin-terminal-missing"
	nativeKeeperStdoutFailure        nativeChildFailure = "keeper-stdout-terminal-missing"
	nativeKeeperRawFailure           nativeChildFailure = "keeper-raw-terminal-failed"
	nativeInteractiveCodeFailure     nativeChildFailure = "interactive-cli-nonzero-code"
	nativeInteractiveErrorFailure    nativeChildFailure = "interactive-cli-error"
	nativeInteractiveTerminalFailure nativeChildFailure = "interactive-cli-terminal"
	nativeInteractiveSaveFailure     nativeChildFailure = "interactive-cli-save"
	nativeInteractiveUnlockFailure   nativeChildFailure = "interactive-cli-unlock"
)

func (trace *nativeTerminalTrace) addInteractiveCLIFailureMarkers() {
	trace.addChildFailureMarkers(nativeInteractiveCodeFailure, nativeInteractiveErrorFailure,
		nativeInteractiveTerminalFailure, nativeInteractiveSaveFailure, nativeInteractiveUnlockFailure)
}

func TestNativeKeeperProcessChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_KEEPER_CHILD") != "1" {
		t.Skip("actual native keeper child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		nativeChildFatal(t, nativeKeeperStdinFailure, "keeper stdin was not a terminal")
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		nativeChildFatal(t, nativeKeeperStdoutFailure, "keeper stdout was not a terminal")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		nativeChildFatal(t, nativeKeeperRawFailure, "keeper could not set stdin raw mode")
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
		t.Fatal("could not resolve the test executable")
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal("could not resolve the terminal bridge")
	}
	for _, cycle := range cycles {
		if !t.Run(cycle, func(t *testing.T) {
			flakediag.Begin(t)
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
			trace := startNativeTerminal(t, t, service, "keeper cycle", ownerterminal.Command{Executable: executable, UnixBridge: bridge,
				Directory: t.TempDir(), Environment: environment, Args: arguments})
			trace.addKeeperHarnessFailureMarkers()
			trace.addChildFailureMarkers(nativeKeeperStdinFailure, nativeKeeperStdoutFailure, nativeKeeperRawFailure)
			trace.addInteractiveCLIFailureMarkers()
			if cycle == "bypass" {
				trace.addFailureMarker("bypass-warning", "WARNING: MCP known-literal output filtering is DISABLED")
			}
			defer func() {
				trace.cleanup(t, "keeper terminal did not close cleanly", "keeper terminal output did not join")
				if trace.capture.Contains(password) {
					t.Error("actual keeper disclosed the vault unlock")
				}
				if trace.capture.Contains([]byte("synthetic native helper credential")) {
					t.Error("actual keeper disclosed the historical add-account credential")
				}
				if trace.capture.Contains([]byte(nativeGuardAddedCredential)) {
					t.Error("actual keeper disclosed the keeper add-account credential")
				}
			}()
			trace.expectText(t, startup, "keeper-unlock", "Vault secret:", "actual keeper did not request its vault unlock")
			ending := byte('\n')
			if runtime.GOOS == "windows" {
				ending = '\r'
			}
			input := append(append([]byte(nil), password...), ending)
			trace.write(t, "keeper-unlock", input)
			trace.expectText(t, startup, "keeper-harness-ready", "ACTUAL-KEEPER-HARNESS-READY", "actual keeper did not start its owned harness")
			if cycle == "bypass" {
				trace.expectText(t, startup, "keeper-bypass-warning", "WARNING: MCP known-literal output filtering is DISABLED", "trusted bypass launch omitted its terminal warning")
			}
			stopStartup()
			probePhase, stopProbe := nativeOperationPhase(t, service, 30*time.Second)
			trace.recordCaptured("keeper-startup-probe", "dial-attempt", "")
			probe, err := ownerlocal.Dial(probePhase, path)
			nativeKeeperEndpointResult(trace, "keeper-startup-probe", "dial-result", probePhase, err)
			stopProbe()
			if err != nil {
				t.Fatal("actual keeper did not hold the native database endpoint")
			}
			trace.recordCaptured("keeper-startup-probe", "close-attempt", "")
			err = probe.Close()
			nativeKeeperEndpointResult(trace, "keeper-startup-probe", "close-result", nil, err)
			if err != nil {
				t.Fatal("actual keeper startup probe did not close")
			}
			observerPhase, stopObserverPhase := nativeOperationPhase(t, service, 2*time.Minute)
			trace.recordCaptured("keeper-observer", "attach-attempt", "")
			observer, err := ownercontrol.Open(service, path, password)
			serviceErr, observerPhaseErr := service.Err(), observerPhase.Err()
			trace.recordCaptured("keeper-observer", "attach-result", "class=%s service=%s phase=%s ",
				nativeResultClass(err, "attach-error"), nativeResultClass(serviceErr, "context-error"), nativeResultClass(observerPhaseErr, "context-error"))
			detachObserver := func() {
				trace.recordCaptured("keeper-observer", "detach-attempt", "")
				observer.Detach()
				trace.recordCaptured("keeper-observer", "detach-result", "class=returned ")
			}
			if err != nil || serviceErr != nil || observerPhaseErr != nil {
				if observer != nil {
					detachObserver()
				}
				stopObserverPhase()
				if err != nil {
					t.Fatal("independent observer could not authenticate")
				}
				if serviceErr != nil {
					t.Fatal("keeper service budget ended during observer attach")
				}
				t.Fatal("independent observer attach exceeded its phase budget")
			}
			stopObserverPhase()
			defer detachObserver()
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
					flakediag.Begin(t)
					nativeHumanSSHAcceptance(t, humanPhase, path, password, server, observer, shell)
				}) {
					stopHuman()
					return
				}
				stopHuman()
				scopePhase, stopScope := nativeOperationPhase(t, service, time.Minute)
				nativeKeeperRestoreHumanScope(t, scopePhase, path, server, observer, shell, trace, func() {
					trace.write(t, "keeper-scope-refusal", []byte{'r', ending})
					trace.expectText(t, scopePhase, "keeper-scope-refused", "ACTUAL-KEEPER-SSH-SCOPE-REFUSED", "actual keeper did not refuse the changed human SSH scope")
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
				trace.recordCaptured("keeper-restart-metadata", "check", "class=%s servers=%d helper-found=%t ", nativeResultClass(err, "metadata-error"), len(metadata.Servers), found)
				if err != nil {
					t.Fatal("restarted actual keeper could not read metadata")
				}
				if !found {
					t.Fatal("restarted actual keeper lost the confirmed helper account")
				}
			} else {
				humanPhase, stopHuman := nativeOperationPhase(t, service, 2*time.Minute)
				if !t.Run("native-human-ssh", func(t *testing.T) {
					flakediag.Begin(t)
					nativeHumanSSHAcceptance(t, humanPhase, path, password, server, observer, shell)
				}) {
					stopHuman()
					return
				}
				stopHuman()
				scopePhase, stopScope := nativeOperationPhase(t, service, time.Minute)
				nativeKeeperRestoreHumanScope(t, scopePhase, path, server, observer, shell, trace, func() {
					trace.write(t, "keeper-scope-refusal", []byte{'r', ending})
					trace.expectText(t, scopePhase, "keeper-scope-refused", "ACTUAL-KEEPER-SSH-SCOPE-REFUSED", "actual keeper did not refuse the changed human SSH scope")
				})
				stopScope()
			}
			observerClose, stopObserverClose := nativeOperationPhase(t, service, 30*time.Second)
			trace.recordCaptured("keeper-observer", "close-attempt", "")
			err = observer.Close(observerClose)
			nativeKeeperEndpointResult(trace, "keeper-observer", "close-result", observerClose, err)
			stopObserverClose()
			if err != nil {
				t.Fatal("independent observer did not close cleanly")
			}
			guardPhase, stopGuard := nativeOperationPhase(t, service, 30*time.Second)
			if !t.Run("native-mcp-guard", func(t *testing.T) {
				trace.expectText(t, guardPhase, "keeper-guard-ready", "ACTUAL-KEEPER-MCP-GUARD-READY", "actual keeper did not guard its initial MCP job")
				trace.write(t, "keeper-guard-refresh", []byte{'g', ending})
				trace.expectText(t, guardPhase, "keeper-guard-refreshed", "ACTUAL-KEEPER-MCP-GUARD-REFRESHED", "actual keeper did not refresh known literals after helper edits")
			}) {
				stopGuard()
				return
			}
			stopGuard()
			probePhase, stopProbe = nativeOperationPhase(t, service, 30*time.Second)
			trace.recordCaptured("keeper-detach-probe", "dial-attempt", "")
			probe, err = ownerlocal.Dial(probePhase, path)
			nativeKeeperEndpointResult(trace, "keeper-detach-probe", "dial-result", probePhase, err)
			stopProbe()
			if err != nil {
				t.Fatal("actual keeper endpoint was unavailable after helper and observer detach")
			}
			trace.recordCaptured("keeper-detach-probe", "close-attempt", "")
			err = probe.Close()
			nativeKeeperEndpointResult(trace, "keeper-detach-probe", "close-result", nil, err)
			if err != nil {
				t.Fatal("actual keeper post-detach probe did not close")
			}
			shutdown, stopShutdown := nativeOperationPhase(t, service, 30*time.Second)
			trace.recordCaptured("keeper-shutdown", "attempt", "")
			trace.write(t, "keeper-shutdown", []byte{'q', ending})
			trace.wait(t, shutdown, "actual keeper did not join graceful harness and owner shutdown")
			trace.expectText(t, shutdown, "keeper-harness-stopped", "ACTUAL-KEEPER-HARNESS-STOPPED", "harness shutdown acknowledgement was lost")
			trace.recordCaptured("keeper-shutdown", "result", "class=acknowledged phase=%s service=%s ",
				nativeResultClass(shutdown.Err(), "context-error"), nativeResultClass(service.Err(), "context-error"))
			stopShutdown()
			stopService()
			reopenCtx, reopenCancel := nativeOperationPhase(t, ctx, time.Minute)
			defer reopenCancel()
			trace.recordCaptured("keeper-endpoint-absence", "dial-attempt", "")
			probe, err = ownerlocal.Dial(reopenCtx, path)
			nativeKeeperEndpointResult(trace, "keeper-endpoint-absence", "dial-result", reopenCtx, err)
			if err == nil {
				trace.recordCaptured("keeper-endpoint-absence", "close-attempt", "")
				err := probe.Close()
				nativeKeeperEndpointResult(trace, "keeper-endpoint-absence", "close-result", nil, err)
				if err != nil {
					t.Fatal("standalone reopen probe did not close")
				}
				t.Fatal("standalone reopen endpoint was still listening")
			}
			if !errors.Is(err, ownerlocal.ErrAbsent) {
				if reopenCtx.Err() != nil {
					t.Fatal("standalone reopen phase budget ended")
				}
				t.Fatal("standalone reopen probe did not confirm endpoint absence")
			}
			trace.recordCaptured("keeper-reopen", "open-attempt", "")
			reopened, err := ownercontrol.Open(reopenCtx, path, password)
			nativeKeeperEndpointResult(trace, "keeper-reopen", "open-result", reopenCtx, err)
			if err != nil {
				if reopenCtx.Err() != nil {
					t.Fatal("standalone reopen phase budget ended")
				}
				t.Fatal("joined keeper shutdown could not reacquire standalone control")
			}
			defer func() {
				cleanup, stop := nativePhaseCleanup(t)
				defer stop()
				trace.recordCaptured("keeper-reopen-cleanup", "close-attempt", "")
				err := reopened.Close(cleanup)
				nativeKeeperEndpointResult(trace, "keeper-reopen-cleanup", "close-result", cleanup, err)
				if err != nil {
					t.Error("standalone control cleanup failed")
				}
			}()
			metadata, err := reopened.Backend().Metadata()
			status := reopened.Backend().Status()
			digest, digestErr := credential.CredentialCipherDigest(path)
			nativeKeeperCheckScope(t, trace, "fresh-reopen", metadata, err, status, server, shell.Address())
			nativeKeeperCheckCipher(t, trace, "fresh-reopen", digest, digestErr)
			trace.recordCaptured("keeper-reclose", "close-attempt", "")
			err = reopened.Close(reopenCtx)
			nativeKeeperEndpointResult(trace, "keeper-reclose", "close-result", reopenCtx, err)
			if err != nil {
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

func nativeKeeperEndpointResult(trace *nativeTerminalTrace, stage, operation string, ctx context.Context, err error) {
	class := nativeResultClass(err, "endpoint-error")
	if errors.Is(err, ownerlocal.ErrAbsent) {
		class = "absent"
	}
	if ctx == nil {
		trace.recordCaptured(stage, operation, "class=%s ", class)
		return
	}
	trace.recordCaptured(stage, operation, "class=%s phase=%s ", class, nativeResultClass(ctx.Err(), "context-error"))
}

func nativeKeeperCheckScope(t *testing.T, trace *nativeTerminalTrace, stage string, metadata vault.DirectoryMetadata, err error, status ownerdb.Status, server, address string) {
	t.Helper()
	trace.recordCaptured(stage, "scope-check", "metadata=%s servers=%d status=%s database=%s pending=%t revision=%d saved-revision=%d ",
		nativeResultClass(err, "metadata-error"), len(metadata.Servers), nativeResultClass(status.Err, "status-error"),
		nativeResultClass(status.Database.Err, "database-error"), status.Database.Pending, status.Database.Revision, status.Database.SavedRevision)
	switch {
	case err != nil:
		t.Fatalf("%s: could not read fixture metadata", stage)
	case len(metadata.Servers) != 1:
		t.Fatalf("%s: expected one fixture server", stage)
	case metadata.Servers[0].ID != server:
		t.Fatalf("%s: fixture server ID changed", stage)
	case metadata.Servers[0].Address != address:
		t.Fatalf("%s: fixture endpoint did not match", stage)
	case status.Err != nil:
		t.Fatalf("%s: owner status reported an error", stage)
	case status.Database.Err != nil:
		t.Fatalf("%s: database status reported an error", stage)
	case status.Database.Pending:
		t.Fatalf("%s: database still had pending changes", stage)
	case status.Database.Revision != status.Database.SavedRevision:
		t.Fatalf("%s: database revision was not saved", stage)
	}
}

func nativeKeeperCheckCipher(t *testing.T, trace *nativeTerminalTrace, stage string, digest [32]byte, err error) {
	t.Helper()
	zero := digest == ([32]byte{})
	trace.recordCaptured(stage, "cipher-check", "class=%s zero=%t ", nativeResultClass(err, "digest-error"), zero)
	if err != nil {
		t.Fatalf("%s: could not read credential cipher digest", stage)
	}
	if zero {
		t.Fatalf("%s: credential cipher digest was zero", stage)
	}
}

func nativeKeeperRestoreHumanScope(t *testing.T, ctx context.Context, path, server string, observer *ownercontrol.Control, shell *sshfixture.LoopbackSSH, trace *nativeTerminalTrace, refuse func()) {
	t.Helper()
	metadata, err := observer.Backend().Metadata()
	status := observer.Backend().Status()
	nativeKeeperCheckScope(t, trace, "changed-scope", metadata, err, status, server, "127.0.0.1:3")
	connections := shell.AcceptedConnections()
	refuse()
	afterRefusal := shell.AcceptedConnections()
	trace.recordCaptured("keeper-scope-refused", "connection-check", "before=%d after=%d ", connections, afterRefusal)
	if afterRefusal != connections {
		t.Fatal("refused changed-scope MCP operation opened an SSH connection")
	}
	trace.recordCaptured("keeper-refusal-probe", "dial-attempt", "")
	probe, err := ownerlocal.Dial(ctx, path)
	nativeKeeperEndpointResult(trace, "keeper-refusal-probe", "dial-result", ctx, err)
	if err != nil {
		t.Fatal("changed-scope refusal released the actual keeper role")
	}
	trace.recordCaptured("keeper-refusal-probe", "close-attempt", "")
	err = probe.Close()
	nativeKeeperEndpointResult(trace, "keeper-refusal-probe", "close-result", nil, err)
	if err != nil {
		t.Fatal("actual keeper role probe did not close")
	}
	nativeServerAddress(t, ctx, observer, server, shell.Address())
	metadata, err = observer.Backend().Metadata()
	status = observer.Backend().Status()
	digest, digestErr := credential.CredentialCipherDigest(path)
	nativeKeeperCheckScope(t, trace, "restored-scope", metadata, err, status, server, shell.Address())
	nativeKeeperCheckCipher(t, trace, "restored-scope", digest, digestErr)
}

func nativeServerAddress(t *testing.T, ctx context.Context, control *ownercontrol.Control, server, address string) {
	t.Helper()
	status := control.Backend().Status()
	if status.Err != nil {
		t.Fatal("observer owner status failed before directory edit")
	}
	if status.Database.Err != nil {
		t.Fatal("observer database status failed before directory edit")
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
		t.Fatalf("observer directory edit failed (%s)", nativeResultClass(err, "edit-error"))
	}
	if err := control.Backend().Flush(ctx); err != nil {
		t.Fatalf("observer directory flush failed (%s)", nativeResultClass(err, "flush-error"))
	}
}

func nativeHumanSSHAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server string, observer *ownercontrol.Control, loopback *sshfixture.LoopbackSSH) {
	t.Helper()
	nativeServerAddress(t, ctx, observer, server, loopback.Address())
	metadata, err := observer.Backend().Metadata()
	if err != nil {
		t.Fatalf("human SSH could not read fixture metadata (%s)", nativeResultClass(err, "metadata-error"))
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
	if name == "" {
		t.Fatal("human SSH fixture server name is missing")
	}
	if human != 1 {
		t.Fatalf("human SSH expected one human account (count=%d)", human)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("could not resolve the test executable")
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal("could not resolve the terminal bridge")
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
	trace := startNativeTerminal(t, t, ctx, "human SSH handoff", ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
		Args: []string{"-test.run=^TestNativeInteractiveProcessChild$", "--", "--vault", path, "--interactive"}})
	trace.addInteractiveTerminalFailureMarkers()
	trace.addInteractiveCLIFailureMarkers()
	defer func() {
		trace.cleanup(t, "", "human SSH terminal output did not join")
		if trace.capture.Contains(password) {
			t.Error("human SSH terminal exposed the vault unlock")
		}
	}()
	trace.expectText(t, ctx, "human-ssh-unlock", "Vault secret:", "human SSH did not request its vault unlock")
	ending := byte('\n')
	if runtime.GOOS == "windows" {
		ending = '\r'
	}
	input := append(append([]byte(nil), password...), ending)
	trace.write(t, "human-ssh-unlock", input)
	trace.expectText(t, ctx, "human-ssh-connect-picker", "Connect:", "human SSH did not show the connect picker")
	// Right must not connect; the following Servers screen is the input barrier.
	trace.write(t, "human-ssh-navigate-to-servers", []byte("\x1b[C\x1b[B\r"))
	trace.expectText(t, ctx, "human-ssh-servers-screen", "[Add server]", "human SSH did not show the servers screen")
	beforeEnter := loopback.AcceptedConnections()
	trace.recordCaptured("human-ssh-servers-screen", "connection-check", "before=%d after=%d ", connections, beforeEnter)
	if beforeEnter != connections {
		t.Fatal("picker connected before an explicit Enter decision")
	}
	trace.write(t, "human-ssh-connect", []byte("\x1b[D\r"))
	trace.expectText(t, ctx, "human-ssh-shell-ready", "SYNTHETIC-SSH-READY user=second", "human SSH did not reach the selected shell")
	if trace.capture.Contains([]byte(sshfixture.ConnectPassword)) {
		t.Fatal("SSH authentication was disclosed before deliberate human output")
	}
	t.Run("legacy-writer-refusal", func(t *testing.T) {
		flakediag.Begin(t)
		nativeWriterRefusal(t, ctx, path, password, name, loopback)
	})
	// Later owner edits must not replace or terminate the captured live shell.
	trace.recordCaptured("human-ssh-scope-edit", "edit-attempt", "")
	nativeServerAddress(t, ctx, observer, server, "127.0.0.1:3")
	trace.recordCaptured("human-ssh-scope-edit", "edit-complete", "")
	trace.write(t, "human-ssh-shell-input", append([]byte(sshfixture.ConnectPassword), '\r'))
	expectNativeHumanSSHEcho(t, trace, ctx, sshfixture.ConnectPassword)
	trace.write(t, "human-ssh-shell-exit", []byte("exit\r"))
	// Fresh metadata replaces the transient exit message after the address edit.
	trace.expectText(t, ctx, "human-ssh-picker-restored", "The list changed; choose an entry again.", "human SSH did not restore the picker with fresh metadata")
	trace.write(t, "human-ssh-picker-close", []byte{3})
	trace.wait(t, ctx, "human shell handoff did not restore and close the picker")
	statuses := loopback.ExitStatuses()
	trace.recordCaptured("human-ssh-exit-status", "count-check", "before=%d after=%d ", exits, len(statuses))
	if len(statuses) != exits+1 {
		t.Fatal("loopback SSH did not send exactly one exit status")
	}
	status := statuses[len(statuses)-1]
	trace.recordCaptured("human-ssh-exit-status", "status-check", "status=%d ", status)
	if status != 0 {
		t.Fatal("loopback SSH exit status was nonzero")
	}
	accepted := loopback.Authentications()
	afterConnections := loopback.AcceptedConnections()
	trace.recordCaptured("human-ssh-handoff", "count-check", "connections-before=%d connections-after=%d authentications-before=%d authentications-after=%d ",
		connections, afterConnections, authentications, len(accepted))
	if afterConnections != connections+1 {
		t.Fatal("native handoff did not open exactly one SSH connection")
	}
	if len(accepted) != authentications+1 {
		t.Fatal("native handoff did not authenticate exactly once")
	}
	account, method, _ := strings.Cut(accepted[len(accepted)-1], "|")
	if account != "second" {
		t.Error("native handoff used the wrong SSH account")
	}
	if method != "password" {
		t.Error("native handoff used the wrong SSH authentication method")
	}
}

// ownerInteractivePTYChild shares the CLI invocation and diagnostics between
// the native keeper and interactive terminal children.
func ownerInteractivePTYChild(t *testing.T) {
	t.Helper()
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
	contextEnded := ctx.Err() != nil
	if code != 0 {
		t.Errorf("%s code=%d context-ended=%t", nativeInteractiveCodeFailure.marker(), code, contextEnded)
	}
	if err != nil {
		class := nativeInteractiveErrorFailure
		switch err.Error() {
		case "owner terminal editor stopped unexpectedly":
			class = nativeInteractiveTerminalFailure
		case "owner editor stopped with unsaved or unresolved changes; reopen the encrypted database and inspect pending recovery":
			class = nativeInteractiveSaveFailure
		case "cannot unlock owner database; directory payload schema v2 is required":
			class = nativeInteractiveUnlockFailure
		}
		nativeChildFatal(t, class, "interactive CLI returned an error (context-ended=%t)", contextEnded)
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
