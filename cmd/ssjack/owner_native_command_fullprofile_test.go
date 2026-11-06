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
	TestOwnerCommandPTYChild(t)
}

func nativeOwnerCommandAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server, account string, control *ownercontrol.Control) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_pty_bridge.py"))
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
			if capture.Wait(lifetime, "Vault secret:") != nil {
				t.Fatal("native owner did not request its single vault unlock")
			}
			ending := byte('\n')
			if runtime.GOOS == "windows" {
				ending = '\r'
			}
			input := append(append([]byte(nil), password...), ending)
			_, err = terminal.Input.Write(input)
			clear(input)
			if err != nil || capture.Wait(lifetime, "Credential:") != nil {
				t.Fatal("native owner did not display its real parameterized form")
			}
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
			if mode == "apply" && capture.Wait(lifetime, "Owner command completed; encrypted persistence confirmed.") != nil {
				t.Fatal("native owner command lacked a persistence receipt")
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
