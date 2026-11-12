package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotationtest"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultOwnerRotationRecoveryFullProfile(t *testing.T) {
	ownerrotationtest.Accept(t)
}

func TestRotationComposedProcessChild(t *testing.T) {
	ownerrotationtest.Child(t, run)
}

func TestOwnerCommandPTYChild(t *testing.T) {
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
	code, err := run(ctx, args)
	if os.Getenv("SSJACK_OWNER_COMMAND_CANCEL") == "1" {
		if code != 1 || !errors.Is(err, ownercommand.ErrCancelled) {
			t.Fatal("cancelled owner command did not refuse")
		}
	} else if code != 0 || err != nil {
		t.Fatal("confirmed owner command failed")
	}
}

func ownerCommandAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server string) {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	name, count := initial.Servers[server].Name, len(initial.Servers[server].Accounts)
	initial.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_command.py"))
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("synthetic CLI account password")
	defer clear(credential)
	input := append(append(append(append([]byte(nil), password...), '\n'), credential...), '\n')
	defer clear(input)
	for _, mode := range []string{"cancel", "apply"} {
		command := exec.CommandContext(ctx, "python3", "-I", driver, executable, path, name, mode)
		command.Stdin = bytes.NewReader(input)
		command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
		command.WaitDelay = 5 * time.Second
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("synthetic owner command: %v: %s", err, output)
		}
		if mode == "cancel" {
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("cancelled command changed database ciphertext")
			}
		}
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	profile, err := loaded.AccountProfile(server, "cli-added")
	if err != nil {
		t.Fatal(err)
	}
	target := loaded.Targets[profile]
	if target.User != "cli-user" || target.Usage != "agent" || !bytes.Equal(target.Password, credential) || len(loaded.Servers[server].Accounts) != count+1 {
		t.Fatal("parameterized command lost metadata/hidden credentials or changed unrelated accounts")
	}
}
