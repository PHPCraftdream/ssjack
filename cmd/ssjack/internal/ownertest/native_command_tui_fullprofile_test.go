package ownertest

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

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestOwnerNativeCommandChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_NATIVE_CHILD") != "1" {
		t.Skip("real native owner terminal child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Fatal("owner child did not receive real terminal handles")
	}
	// Like the existing tmux driver's stty -echo, protect the prompt boundary.
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), state)
	ownerCommandPTYChild(t)
}

// ownerCommandPTYChild mirrors the owneracceptance owner-command PTY child:
// the helper contents were copied verbatim (same environment switches, same
// cli.Run invocation) and renamed to a local helper instead of a second Test.
func ownerCommandPTYChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_COMMAND_CHILD") != "1" {
		t.Skip("synthetic owner-command terminal child only")
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 170*time.Second)
	defer cancel()
	code, err := cli.Run(ctx, args)
	if os.Getenv("SSJACK_OWNER_COMMAND_CANCEL") == "1" {
		if code != 1 || !errors.Is(err, ownercommand.ErrCancelled) {
			t.Fatal("cancelled owner command did not refuse")
		}
	} else if code != 0 || err != nil {
		t.Fatal("confirmed owner command failed")
	}
}

type nativeTerminalTrace struct {
	started    time.Time
	terminal   *ownerterminal.Terminal
	capture    *ownerterminal.Capture
	events     strings.Builder
	screenRows string
	screenNote string
}

func startNativeTerminal(t, diagnostics *testing.T, ctx context.Context, label string, command ownerterminal.Command) *nativeTerminalTrace {
	t.Helper()
	started := time.Now()
	terminal, err := ownerterminal.Start(ctx, command)
	if err != nil {
		t.Fatal("native terminal start failed")
	}
	trace := &nativeTerminalTrace{started: started, terminal: terminal}
	ownerChildTerminal(diagnostics, label, command.Executable, terminal, nil, started)
	flakediag.OnFailure(diagnostics, func() string {
		return label + " timeline:\n" + trace.events.String() + trace.screenNote + trace.screenRows
	})
	trace.capture = ownerterminal.CaptureOutput(terminal.Output)
	trace.record("start", "capture-bytes=%d", trace.capture.Len())
	return trace
}

func (trace *nativeTerminalTrace) record(stage, format string, args ...any) {
	fmt.Fprintf(&trace.events, "+%s %s ", time.Since(trace.started), stage)
	fmt.Fprintf(&trace.events, format, args...)
	trace.events.WriteByte('\n')
}

func (trace *nativeTerminalTrace) write(t *testing.T, stage string, data []byte) {
	t.Helper()
	defer clear(data)
	trace.record(stage, "write-attempt requested=%d capture-bytes=%d", len(data), trace.capture.Len())
	n, err := trace.terminal.Input.Write(data)
	trace.record(stage, "write-complete n=%d error-present=%t capture-bytes=%d", n, err != nil, trace.capture.Len())
	if err != nil || n != len(data) {
		t.Fatalf("%s: terminal write failed or was short", stage)
	}
}

func (trace *nativeTerminalTrace) expect(t *testing.T, ctx context.Context, stage, failure string, match func([]byte) bool) {
	t.Helper()
	trace.record(stage, "expect-attempt capture-bytes=%d", trace.capture.Len())
	matchedBytes := 0
	err := trace.capture.WaitFor(ctx, func(data []byte) bool {
		if !match(data) {
			return false
		}
		matchedBytes = len(data)
		return true
	})
	if err != nil {
		reason := "unexpected wait failure"
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			reason = "deadline exceeded"
		case errors.Is(err, context.Canceled):
			reason = "context canceled"
		case errors.Is(err, ownerterminal.ErrTerminal):
			reason = "output ended or capture overflowed"
		}
		trace.record(stage, "expect-failed reason=%s capture-bytes=%d", reason, trace.capture.Len())
		t.Fatalf("%s: %s (%s)", stage, failure, reason)
	}
	trace.record(stage, "expect-matched capture-bytes=%d", matchedBytes)
}

func (trace *nativeTerminalTrace) expectText(t *testing.T, ctx context.Context, stage, text, failure string) {
	t.Helper()
	trace.expect(t, ctx, stage, failure, func(data []byte) bool {
		return bytes.Contains(data, []byte(text))
	})
}

func (trace *nativeTerminalTrace) wait(t *testing.T, ctx context.Context, failure string) {
	t.Helper()
	trace.record("child-wait", "wait-attempt capture-bytes=%d", trace.capture.Len())
	err := trace.terminal.Wait(ctx)
	trace.record("child-wait", "wait-complete error-present=%t capture-bytes=%d", err != nil, trace.capture.Len())
	if err != nil {
		t.Fatal(failure)
	}
}

func (trace *nativeTerminalTrace) finish(joinFailure string, t *testing.T, inputs ...[]byte) bool {
	t.Helper()
	cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	_ = trace.terminal.Close(cleanup)
	joinErr := trace.capture.Join(cleanup)
	if joinErr != nil {
		t.Error(joinFailure)
	}
	leaked := false
	trace.capture.Inspect(func(data []byte, total int, overflow bool) {
		partial := overflow || joinErr != nil
		trace.record("finish", "capture-retained-bytes=%d capture-total-bytes=%d retained-digest=%s partial=%t join-error-present=%t",
			len(data), total, flakediag.Short(data), partial, joinErr != nil)
		stripped := []byte(ansi.Strip(string(data)))
		defer clear(stripped)
		for _, input := range inputs {
			if len(input) != 0 {
				rawMatch := bytes.Contains(data, input)
				strippedMatch := bytes.Contains(stripped, input)
				leaked = rawMatch || strippedMatch || leaked
			}
		}
		trace.screenDiagnostics(data, partial, inputs...)
	})
	return leaked
}

func (trace *nativeTerminalTrace) screenDiagnostics(prefix []byte, partial bool, inputs ...[]byte) {
	screen := replayNativeCredentialScreenForDiagnostics(prefix)
	rows := []byte(screen.diagnosticRows())
	trace.screenRows = string(renderNativeRedaction(rows, nativeRedactionMask(rows, inputs...)))
	clear(rows)
	trace.screenNote = fmt.Sprintf("screen replay (ignored=%d):\n", screen.ignored)
	if partial || screen.ignored != 0 {
		trace.screenNote += "screen picture may be incomplete\n"
	}
}

func nativeRedactionMask(data []byte, inputs ...[]byte) []bool {
	mask := make([]bool, len(data))
	for _, input := range inputs {
		if len(input) == 0 {
			continue
		}
		// Every full input of length >= 4 is covered by its overlapping windows.
		width := min(4, len(input))
		for i := 0; i+width <= len(input); i++ {
			window := input[i : i+width]
			for start := 0; start+width <= len(data); {
				n := bytes.Index(data[start:], window)
				if n < 0 {
					break
				}
				start += n
				for j := range mask[start : start+width] {
					mask[start+j] = true
				}
				start++ // Do not skip overlapping occurrences of the same window.
			}
		}
	}
	return mask
}

func renderNativeRedaction(data []byte, mask []bool) []byte {
	var safe []byte
	for i, b := range data {
		if !mask[i] {
			safe = append(safe, b)
		} else if i == 0 || !mask[i-1] {
			safe = append(safe, "███"...)
		}
	}
	return safe
}

func TestNativeScreenDiagnosticsMasksEcho(t *testing.T) {
	const credential = "sensitive-value"
	const password = "unlock-value"
	trace := &nativeTerminalTrace{}
	trace.screenDiagnostics([]byte("Credential: hidden\r\nEcho: sensitive-\x1b[31mvalue\x1b[0m\r\nUnlock: unlock-value"), true, []byte(credential), []byte(password))
	if strings.Contains(trace.screenRows, credential) || strings.Contains(trace.screenRows, password) ||
		!strings.Contains(trace.screenRows, "Credential: <redacted>") ||
		!strings.Contains(trace.screenRows, "Echo: ███") || !strings.Contains(trace.screenRows, "Unlock: ███") {
		t.Error("screen diagnostics did not mask hidden input")
	}
	if !strings.Contains(trace.screenNote, "ignored=2") || !strings.Contains(trace.screenNote, "screen picture may be incomplete") {
		t.Error("partial screen diagnostics lost the replay status")
	}
}

func nativeUnlockInput(password []byte) []byte {
	input := make([]byte, len(password)+1)
	copy(input, password)
	input[len(password)] = '\n'
	if runtime.GOOS == "windows" {
		input[len(password)] = '\r'
	}
	return input
}

func nativeOwnerCommandAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server, account string, control *ownercontrol.Control) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := control.Backend().Metadata()
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, entry := range metadata.Servers {
		if entry.ID == server {
			name = entry.Name
		}
	}
	if name == "" {
		t.Fatal("native owner server selection is unavailable")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	revision := control.Backend().Status().Database.Revision
	credentialText := "synthetic native helper credential"
	if account == "keeper-added" {
		credentialText = nativeGuardAddedCredential
	}
	credential := []byte(credentialText)
	defer clear(credential)
	for _, mode := range []string{"cancel", "apply"} {
		func() {
			lifetime, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			environment := make([]string, 0)
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
					environment = append(environment, entry)
				}
			}
			cancelled := "0"
			if mode == "cancel" {
				cancelled = "1"
			}
			environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_NATIVE_CHILD=1", "SSJACK_OWNER_COMMAND_CHILD=1", "SSJACK_OWNER_COMMAND_CANCEL="+cancelled)
			trace := startNativeTerminal(t, t, lifetime, "native owner command "+mode, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Environment: environment,
				Args: []string{"-test.run=^TestOwnerNativeCommandChild$", "--", "--vault", path, "owner", "add-account", "--server", name, "--account", account, "--login", "native-user", "--auth", "password", "--usage", "agent"}})
			defer trace.capture.Clear()
			defer func() {
				if trace.finish("native owner terminal output did not join", t, password, credential) {
					t.Error("native owner terminal disclosed hidden input")
				}
			}()
			trace.expectText(t, lifetime, "vault-prompt", "Vault secret:", "native owner did not request its single vault unlock")
			trace.write(t, "unlock", nativeUnlockInput(password))
			if mode == "cancel" {
				trace.expectText(t, lifetime, "first-tui-frame", "Credential:", "native owner did not display its real parameterized form")
				input := make([]byte, len(credential)+1)
				copy(input, credential)
				input[len(credential)] = '\x1b'
				trace.write(t, "credential-and-cancel", input)
			} else {
				screen := newNativeCredentialScreen()
				trace.expect(t, lifetime, "first-tui-frame", "native owner did not display its real parameterized form", func(data []byte) bool {
					return screen.matches(data, "> Credential: <hidden; empty>")
				})
				// On Windows one credential write can still arrive in multiple console batches.
				trace.write(t, "credential", bytes.Clone(credential))
				trace.expect(t, lifetime, "credential-entered", "native owner did not display its focused hidden-entered credential", func(data []byte) bool {
					return screen.matches(data, "> Credential: <hidden; entered>")
				})
				trace.write(t, "apply", []byte{'\t', '\r'})
			}
			trace.wait(t, lifetime, "native owner command did not finish its explicit decision")
			if mode == "apply" {
				trace.expectText(t, lifetime, "persistence-receipt", "Owner command completed; encrypted persistence confirmed.", "native owner command lacked a persistence receipt")
			}
		}()
		after, err := os.ReadFile(path)
		if err != nil || (mode == "cancel" && !bytes.Equal(before, after)) {
			t.Fatal("cancelled native helper changed encrypted database bytes")
		}
		if _, err := control.Backend().Metadata(); err != nil {
			t.Fatal("native helper detach closed its parent coordinator")
		}
	}
	status := control.Backend().Status()
	if status.Database.Revision != revision+1 || status.Database.SavedRevision != status.Database.Revision || status.Database.Err != nil {
		t.Fatal("native helper bypassed parent RAM admission or saved revision")
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal("native helper persisted vault could not be loaded")
	}
	defer loaded.Close()
	profile, err := loaded.AccountProfile(server, account)
	if err != nil {
		t.Fatal("native helper persisted account profile could not be resolved")
	}
	target := loaded.Targets[profile]
	if target.User != "native-user" {
		t.Fatal("native helper persisted the wrong account user")
	}
	if !bytes.Equal(target.Password, credential) {
		offset := 0
		for offset < len(target.Password) && offset < len(credential) && target.Password[offset] == credential[offset] {
			offset++
		}
		t.Fatalf("native helper persisted the wrong hidden credential: got-length=%d want-length=%d first-differing-offset=%d", len(target.Password), len(credential), offset)
	}
}

func TestNativeInteractiveProcessChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_NATIVE_TUI_CHILD") != "1" {
		t.Skip("actual native interactive child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Fatal("interactive child did not receive real terminal handles")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), state)
	ownerInteractivePTYChild(t)
}

func nativeInteractiveAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server string, observer *ownercontrol.Control) {
	t.Helper()
	metadata, err := observer.Backend().Metadata()
	if err != nil {
		t.Fatal(err)
	}
	connections, index, oldAddress := 0, -1, ""
	for position, entry := range metadata.Servers {
		if entry.ID == server {
			index, oldAddress = position, entry.Address
		}
		for _, account := range entry.Accounts {
			if account.Usage == "" || account.Usage == "both" || account.Usage == "human" {
				connections++
			}
		}
	}
	if index < 0 || connections < 1 || oldAddress == "" {
		t.Fatal("interactive navigation metadata is incomplete")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	revision := observer.Backend().Status().Database.Revision
	const replacement = "127.0.0.1:2"
	outerT := t
	for _, mode := range []string{"cancel", "apply"} {
		t.Run(mode, func(t *testing.T) {
			lifetime, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			environment := make([]string, 0)
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
					environment = append(environment, entry)
				}
			}
			environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_NATIVE_TUI_CHILD=1", "SSJACK_OWNER_TUI_CHILD=1")
			trace := startNativeTerminal(t, outerT, lifetime, "interactive helper "+mode, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
				Args: []string{"-test.run=^TestNativeInteractiveProcessChild$", "--", "--vault", path, "--interactive"}})
			defer trace.capture.Clear()
			defer func() {
				leaked := trace.finish("interactive terminal output did not join", t, password)
				if leaked || trace.capture.Contains([]byte("SSH connection failed")) {
					t.Error("interactive helper exposed input or connected without an explicit connection decision")
				}
			}()
			trace.expectText(t, lifetime, "vault-prompt", "Vault secret:", "actual interactive navigation did not reach: Vault secret:")
			trace.write(t, "unlock", nativeUnlockInput(password))
			trace.expectText(t, lifetime, "first-tui-frame", "Connect:", "actual interactive navigation did not reach: Connect:")
			trace.write(t, "open-server-list", []byte(strings.Repeat("\x1b[B", connections)+"\r"))
			trace.expectText(t, lifetime, "server-list", "[Add server]", "actual interactive navigation did not reach: [Add server]")
			trace.write(t, "select-server", []byte(strings.Repeat("\x1b[B", index+1)+"\r"))
			trace.expectText(t, lifetime, "server-actions", "[Edit server connection]", "actual interactive navigation did not reach: [Edit server connection]")
			trace.write(t, "open-connection-editor", []byte("\x1b[B\r"))
			trace.expectText(t, lifetime, "connection-editor", "Replacement host keys", "actual interactive navigation did not reach: Replacement host keys")
			trace.write(t, "replace-address", append(bytes.Repeat([]byte{127}, len(oldAddress)), []byte(replacement)...))
			if mode == "cancel" {
				trace.write(t, "cancel-and-close", []byte{3, 3})
			} else {
				trace.write(t, "apply", []byte{'\t', '\t', '\r'})
				trace.expectText(t, lifetime, "persistence-receipt", "Change applied. Check persistence status below.", "actual interactive navigation did not reach: Change applied. Check persistence status below.")
				trace.write(t, "close", []byte{3})
			}
			trace.wait(t, lifetime, "actual interactive helper did not finish its close/flush")
			if mode == "cancel" {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("cancelled interactive form changed database ciphertext")
				}
			}
		})
	}
	metadata, err = observer.Backend().Metadata()
	found := false
	for _, entry := range metadata.Servers {
		found = found || entry.ID == server && entry.Address == replacement
	}
	status := observer.Backend().Status()
	if err != nil || !found || status.Database.Revision != revision+1 || status.Database.SavedRevision != status.Database.Revision || status.Database.Err != nil {
		t.Fatal("interactive helper did not update and persist its live parent coordinator")
	}
}
