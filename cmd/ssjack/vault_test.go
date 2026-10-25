package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestVaultArguments(t *testing.T) {
	for _, args := range [][]string{{"init"}, {"list"}, {"passwd"}, {"add", "target"}, {"edit", "target"}, {"show", "target"}, {"remove", "target"}, {"public", "target"}, {"import", "target", "input"}, {"export", "target", "output"}} {
		if err := validateVaultArgs(args); err != nil {
			t.Fatalf("valid arguments %v: %v", args, err)
		}
	}
	for _, args := range [][]string{nil, {"unknown"}, {"list", "extra"}, {"show"}, {"add", "../name"}, {"remove", "target", "extra"}, {"import", "target"}, {"export", "target", ""}} {
		if err := validateVaultArgs(args); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
	for _, args := range [][]string{
		{"ssh", "target", "vault", "list"},
		{"--generate-key", "key", "ssh", "target"},
		{"ssh", "../target"},
		{"vault", "unknown"},
	} {
		if code, err := run(context.Background(), args); code == 0 || err == nil {
			t.Fatalf("invalid mode combination accepted: %v", args)
		}
	}
}

func TestCredentialCommandsRequireInteractiveSecret(t *testing.T) {
	dir := t.TempDir()
	input, err := os.CreateTemp(dir, "nonterminal")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previous := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previous }()
	t.Setenv("SSJACK_PASSPHRASE", "environment secrets must not be accepted")
	for _, args := range [][]string{
		{"vault", "init"}, {"list"}, {"show"},
		{"add"}, {"edit"},
		{"remove"}, {"vault", "passwd"}, {"check"}, {"hostkey", "show"}, {"hostkey", "replace", "input"}, {"rotate"}, {"vault", "check", "input"}, {"vault", "restore", "input"}, {"key", "public"}, {"key", "import", "input"}, {"key", "export", "output"}, {"ssh"}, {"run", "claude", "-c"}, {"claude", "-c"},
	} {
		command := append([]string{"--vault", filepath.Join(dir, "vault")}, args...)
		code, err := run(context.Background(), command)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Fatalf("command bypassed interactive input: %v: %d %v", args, code, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "vault")); !os.IsNotExist(err) {
		t.Fatal("vault was created without interactive confirmation")
	}
}

func TestPlaintextImportDoesNotModifySource(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	block, err := ssh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	original := pem.EncodeToMemory(block)
	path := filepath.Join(t.TempDir(), "input-key")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	imported, err := readImportedPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(imported)
	signer, err := ssh.ParsePrivateKey(imported)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(key.Public())
	if err != nil || !bytes.Equal(public.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatal("plaintext source identity changed")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("source key file was modified")
	}
}

func TestRawTerminalRestoration(t *testing.T) {
	for _, shellFails := range []bool{false, true} {
		entered, restored := 0, 0
		failure := errors.New("shell failed")
		code, err := withRawTerminal(func() (func() error, error) {
			entered++
			return func() error { restored++; return nil }, nil
		}, func(ready func() error) (int, error) {
			if err := ready(); err != nil {
				return 1, err
			}
			if shellFails {
				return 1, failure
			}
			return 0, nil
		})
		if entered != 1 || restored != 1 || (shellFails && (code != 1 || !errors.Is(err, failure))) || (!shellFails && (code != 0 || err != nil)) {
			t.Fatalf("terminal lifecycle: entered=%d restored=%d code=%d err=%v", entered, restored, code, err)
		}
	}
}

func TestRawTerminalIsNotEnteredBeforeSSHReady(t *testing.T) {
	entered := false
	_, _ = withRawTerminal(func() (func() error, error) {
		entered = true
		return func() error { return nil }, nil
	}, func(_ func() error) (int, error) {
		return 1, errors.New("host rejected")
	})
	if entered {
		t.Fatal("terminal changed before host authentication and PTY acceptance")
	}
}

func TestRawTerminalEnterAndRestoreErrors(t *testing.T) {
	failure := errors.New("terminal failure")
	if _, err := withRawTerminal(func() (func() error, error) {
		return nil, failure
	}, func(ready func() error) (int, error) {
		return 1, ready()
	}); !errors.Is(err, failure) {
		t.Fatal("raw terminal setup error was lost")
	}
	if code, err := withRawTerminal(func() (func() error, error) {
		return func() error { return failure }, nil
	}, func(ready func() error) (int, error) {
		return 0, ready()
	}); code != 1 || !errors.Is(err, failure) {
		t.Fatal("terminal restoration error was lost")
	}
}
