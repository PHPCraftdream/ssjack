package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestOwnerInteractivePTYChild(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	code, err := run(ctx, args)
	if code != 0 || err != nil {
		t.Fatal("synthetic interactive child failed")
	}
}

func ownerTerminalAcceptance(t *testing.T, ctx context.Context, path string, password []byte, expected *vault.Vault, server string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatal("owner terminal acceptance requires the Linux CI fixture")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_tui.py"))
	if err != nil {
		t.Fatal(err)
	}
	input := append(append([]byte(nil), password...), '\n')
	defer clear(input)
	command := exec.CommandContext(ctx, "python3", "-I", driver, executable, path)
	command.Stdin = bytes.NewReader(input)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("synthetic owner terminal interaction: %v: %s", err, output)
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if loaded.Servers[server].Name != "pty-renamed" || len(loaded.Targets) != len(expected.Targets) || len(loaded.Servers[server].Accounts) != len(expected.Servers[server].Accounts) || loaded.OwnerStore.Pending != nil {
		t.Fatal("terminal apply/cancel did not preserve the complete directory")
	}
	for profile, target := range expected.Targets {
		actual, exists := loaded.Targets[profile]
		if !exists || actual.Address != target.Address || actual.User != target.User || !bytes.Equal(actual.PrivateKey, target.PrivateKey) || !bytes.Equal(actual.Password, target.Password) {
			t.Fatal("terminal editing changed an unrelated SSH credential")
		}
	}
}
