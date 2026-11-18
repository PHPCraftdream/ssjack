package ownertest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
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
	credential := []byte("synthetic native helper credential")
	if account == "keeper-added" {
		credential = []byte(nativeGuardAddedCredential)
	}
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
			terminal, err := ownerterminal.Start(lifetime, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Environment: environment,
				Args: []string{"-test.run=^TestOwnerNativeCommandChild$", "--", "--vault", path, "owner", "add-account", "--server", name, "--account", account, "--login", "native-user", "--auth", "password", "--usage", "agent"}})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			tail := newOwnerChildTail()
			terminal.Output = teeOwnerChildOutput(terminal.Output, tail)
			ownerChildTerminal(t, "native owner command "+mode, executable, terminal, tail, started)
			capture := ownerterminal.CaptureOutput(terminal.Output)
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
				defer stop()
				_ = terminal.Close(cleanup)
				if capture.Join(cleanup) != nil {
					t.Error("native owner terminal output did not join")
				}
				if capture.Contains(password) || capture.Contains(credential) {
					t.Error("native owner terminal disclosed hidden input")
				}
				capture.Clear()
			}()
			captureWaitDiag(t, lifetime, capture, "Vault secret:", "native owner did not request its single vault unlock")
			ending := byte('\n')
			if runtime.GOOS == "windows" {
				ending = '\r'
			}
			input := append(append([]byte(nil), password...), ending)
			_, err = terminal.Input.Write(input)
			clear(input)
			if err != nil {
				t.Fatal("native owner unlock input failed")
			}
			captureWaitDiag(t, lifetime, capture, "Credential:", "native owner did not display its real parameterized form")
			input = append([]byte(nil), credential...)
			if mode == "cancel" {
				input = append(input, '\x1b')
			} else {
				input = append(input, '\t', '\r')
			}
			_, err = terminal.Input.Write(input)
			clear(input)
			if err != nil || terminal.Wait(lifetime) != nil {
				t.Fatal("native owner command did not finish its explicit decision")
			}
			if mode == "apply" {
				captureWaitDiag(t, lifetime, capture, "Owner command completed; encrypted persistence confirmed.", "native owner command lacked a persistence receipt")
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
		t.Fatal(err)
	}
	defer loaded.Close()
	profile, err := loaded.AccountProfile(server, account)
	if err != nil || loaded.Targets[profile].User != "native-user" || !bytes.Equal(loaded.Targets[profile].Password, credential) {
		t.Fatal("native helper lost its confirmed hidden credential or directory selection")
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
			terminal, err := ownerterminal.Start(lifetime, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
				Args: []string{"-test.run=^TestNativeInteractiveProcessChild$", "--", "--vault", path, "--interactive"}})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			tail := newOwnerChildTail()
			terminal.Output = teeOwnerChildOutput(terminal.Output, tail)
			ownerChildTerminal(t, "interactive helper "+mode, executable, terminal, tail, started)
			capture := ownerterminal.CaptureOutput(terminal.Output)
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
				defer stop()
				_ = terminal.Close(cleanup)
				if capture.Join(cleanup) != nil {
					t.Error("interactive terminal output did not join")
				}
				if capture.Contains(password) || capture.Contains([]byte("SSH connection failed")) {
					t.Error("interactive helper exposed input or connected without an explicit connection decision")
				}
				capture.Clear()
			}()
			expect := func(text string) {
				captureWaitDiag(t, lifetime, capture, text, "actual interactive navigation did not reach: "+text)
			}
			send := func(data []byte) {
				if _, err := terminal.Input.Write(data); err != nil {
					t.Fatal("interactive terminal input failed")
				}
			}
			expect("Vault secret:")
			ending := byte('\n')
			if runtime.GOOS == "windows" {
				ending = '\r'
			}
			input := append(append([]byte(nil), password...), ending)
			send(input)
			clear(input)
			expect("Connect:")
			send([]byte(strings.Repeat("\x1b[B", connections) + "\r"))
			expect("[Add server]")
			send([]byte(strings.Repeat("\x1b[B", index+1) + "\r"))
			expect("[Edit server connection]")
			send([]byte("\x1b[B\r"))
			expect("Replacement host keys")
			send(append(bytes.Repeat([]byte{127}, len(oldAddress)), []byte(replacement)...))
			if mode == "cancel" {
				send([]byte{3, 3})
			} else {
				send([]byte{'\t', '\t', '\r'})
				expect("Change applied. Check persistence status below.")
				send([]byte{3})
			}
			if terminal.Wait(lifetime) != nil {
				t.Fatal("actual interactive helper did not finish its close/flush")
			}
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
