package main

import (
	"context"
	"fmt"
	"io"
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

func TestNativeKeeperHarnessChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_KEEPER_CHILD") != "1" {
		t.Skip("owned finite keeper harness only")
	}
	fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-HARNESS-READY")
	var command [1]byte
	if _, err := io.ReadFull(os.Stdin, command[:]); err != nil || command[0] != 'q' {
		t.Fatal("keeper harness did not receive its graceful exit request")
	}
	fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-HARNESS-STOPPED")
}

func nativeKeeperProcessAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server, name string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cycle := range []string{"edit", "restart"} {
		t.Run(cycle, func(t *testing.T) {
			lifetime, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			environment := make([]string, 0)
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
					environment = append(environment, entry)
				}
			}
			environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_KEEPER_CHILD=1", "SSJACK_OWNER_TUI_CHILD=1", "SSJACK_OWNER_TUI_CHILD_SECONDS=180")
			terminal, err := ownerterminal.Start(lifetime, ownerterminal.Command{Executable: executable, UnixBridge: bridge,
				Directory: t.TempDir(), Environment: environment,
				Args: []string{"-test.run=^TestNativeKeeperProcessChild$", "--", "--vault", path, "--server", name, "--account", "main", "run", executable, "-test.run=^TestNativeKeeperHarnessChild$"}})
			if err != nil {
				t.Fatal(err)
			}
			capture := ownerterminal.CaptureOutput(terminal.Output)
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
				defer stop()
				_ = terminal.Close(cleanup)
				if capture.Join(cleanup) != nil {
					t.Error("keeper terminal output did not join")
				}
				if capture.Contains(password) || capture.Contains([]byte("synthetic native helper credential")) {
					t.Error("actual keeper disclosed private input")
				}
				capture.Clear()
			}()
			if capture.Wait(lifetime, "Vault secret:") != nil {
				t.Fatal("actual keeper did not request its vault unlock")
			}
			ending := byte('\n')
			if runtime.GOOS == "windows" {
				ending = '\r'
			}
			input := append(append([]byte(nil), password...), ending)
			_, err = terminal.Input.Write(input)
			clear(input)
			if err != nil || capture.Wait(lifetime, "ACTUAL-KEEPER-HARNESS-READY") != nil {
				t.Fatal("actual keeper did not start its owned harness")
			}
			probe, err := ownerlocal.Dial(lifetime, path)
			if err != nil {
				t.Fatal("actual keeper did not hold the native database endpoint")
			}
			if err := probe.Close(); err != nil {
				t.Fatal(err)
			}
			observer, err := ownercontrol.Open(lifetime, path, password)
			if err != nil {
				t.Fatal("independent observer could not authenticate to actual keeper")
			}
			defer observer.Detach()
			if cycle == "edit" {
				nativeOwnerCommandAcceptance(t, lifetime, path, password, server, "keeper-added", observer)
			} else {
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
			}
			if err := observer.Close(lifetime); err != nil {
				t.Fatal(err)
			}
			probe, err = ownerlocal.Dial(lifetime, path)
			if err != nil {
				t.Fatal("helper or observer detach released the actual keeper role")
			}
			_ = probe.Close()
			if _, err := terminal.Input.Write([]byte{'q', ending}); err != nil || terminal.Wait(lifetime) != nil {
				t.Fatal("actual keeper did not join graceful harness and owner shutdown")
			}
			if capture.Wait(lifetime, "ACTUAL-KEEPER-HARNESS-STOPPED") != nil {
				t.Fatal("harness shutdown acknowledgement was lost")
			}
			reopened, err := ownercontrol.Open(lifetime, path, password)
			if err != nil {
				t.Fatal("joined actual keeper shutdown retained the writer role")
			}
			if err := reopened.Close(lifetime); err != nil {
				t.Fatal(err)
			}
		})
	}
}
