package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
)

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
	TestOwnerInteractivePTYChild(t)
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
	bridge, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_pty_bridge.py"))
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
				if capture.Wait(lifetime, text) != nil {
					t.Fatal("actual interactive navigation did not reach:", text)
				}
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
