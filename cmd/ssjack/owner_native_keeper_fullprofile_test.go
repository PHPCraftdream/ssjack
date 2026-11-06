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
	for _, argument := range os.Args[1:] {
		if argument == "--no-output-filter" {
			t.Fatal("root output-filter option was forwarded to the harness")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	session := nativeGuardHarnessSession(t, ctx)
	nativeGuardHarnessCheck(t, ctx, session, false)
	fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-MCP-GUARD-READY")
	fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-HARNESS-READY")
	for {
		var command [1]byte
		if _, err := io.ReadFull(os.Stdin, command[:]); err != nil {
			t.Fatal("keeper harness did not receive its graceful exit request")
		}
		switch command[0] {
		case 'q':
			fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-HARNESS-STOPPED")
			return
		case 'g':
			nativeGuardHarnessCheck(t, ctx, session, true)
			fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-MCP-GUARD-REFRESHED")
		case '\r', '\n':
		default:
			t.Fatal("keeper harness received an unexpected fixture command")
		}
	}
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
			arguments := []string{"-test.run=^TestNativeKeeperProcessChild$", "--", "--vault", path, "--server", name, "--account", "main"}
			if cycle == "bypass" {
				arguments = append(arguments, "--no-output-filter")
				environment = append(environment, "SSJACK_OWNER_GUARD_BYPASS_CHILD=1")
			}
			arguments = append(arguments, "run", executable, "-test.run=^TestNativeKeeperHarnessChild$")
			terminal, err := ownerterminal.Start(lifetime, ownerterminal.Command{Executable: executable, UnixBridge: bridge,
				Directory: t.TempDir(), Environment: environment, Args: arguments})
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
				if capture.Contains(password) || capture.Contains([]byte("synthetic native helper credential")) || capture.Contains([]byte(nativeGuardAddedCredential)) {
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
			if cycle == "bypass" && capture.Wait(lifetime, "WARNING: MCP known-literal output filtering is DISABLED") != nil {
				t.Fatal("trusted bypass launch omitted its terminal warning")
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
				t.Run("native-interactive-helper", func(t *testing.T) {
					nativeInteractiveAcceptance(t, lifetime, path, password, server, observer)
				})
				t.Run("native-human-ssh", func(t *testing.T) {
					nativeHumanSSHAcceptance(t, lifetime, path, password, server, observer, shell)
				})
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
				t.Run("native-human-ssh", func(t *testing.T) {
					nativeHumanSSHAcceptance(t, lifetime, path, password, server, observer, shell)
				})
			}
			if err := observer.Close(lifetime); err != nil {
				t.Fatal(err)
			}
			t.Run("native-mcp-guard", func(t *testing.T) {
				if capture.Wait(lifetime, "ACTUAL-KEEPER-MCP-GUARD-READY") != nil {
					t.Fatal("actual keeper did not guard its initial MCP job")
				}
				if _, err := terminal.Input.Write([]byte{'g', ending}); err != nil || capture.Wait(lifetime, "ACTUAL-KEEPER-MCP-GUARD-REFRESHED") != nil {
					t.Fatal("actual keeper did not refresh known literals after helper edits")
				}
			})
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
			nativeServerAddress(t, lifetime, reopened, server, shell.address())
			if err := reopened.Close(lifetime); err != nil {
				t.Fatal(err)
			}
		})
	}
}
