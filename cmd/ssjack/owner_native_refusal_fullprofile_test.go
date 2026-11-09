package main

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

	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestNativeWriterRefusalChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_NATIVE_REFUSAL_CHILD") != "1" {
		t.Skip("actual native writer refusal child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Fatal("writer refusal child lacks a real terminal")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), state)
	var args []string
	for index, value := range os.Args {
		if value == "--" {
			args = os.Args[index+1:]
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if code, err := run(ctx, args); code != 1 || !errors.Is(err, vault.ErrWriterRole) {
		t.Fatal("actual legacy writer did not refuse at native role admission")
	}
	fmt.Fprintln(os.Stdout, "ACTUAL-LEGACY-WRITER-REFUSED")
}

func nativeWriterRefusal(t *testing.T, ctx context.Context, path string, password []byte, name string, server *loopbackSSH) {
	t.Helper()
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
	connections := server.acceptedConnections()
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "SSJACK_OWNER_NATIVE_REFUSAL_CHILD=1")
	terminal, err := ownerterminal.Start(ctx, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
		Args: []string{"-test.run=^TestNativeWriterRefusalChild$", "--", "--vault", path, "--server", name, "--account", "key-only", "rotate"}})
	if err != nil {
		t.Fatal(err)
	}
	capture := ownerterminal.CaptureOutput(terminal.Output)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = terminal.Close(cleanup)
		if capture.Join(cleanup) != nil || capture.Contains(password) {
			t.Error("writer refusal did not join safely or exposed hidden input")
		}
		capture.Clear()
	}()
	if capture.Wait(ctx, "Vault secret:") != nil {
		t.Fatal("actual legacy writer did not request its unlock")
	}
	ending := byte('\n')
	if runtime.GOOS == "windows" {
		ending = '\r'
	}
	input := append(append([]byte(nil), password...), ending)
	_, err = terminal.Input.Write(input)
	clear(input)
	if err != nil || terminal.Wait(ctx) != nil || capture.Wait(ctx, "ACTUAL-LEGACY-WRITER-REFUSED") != nil {
		t.Fatal("actual legacy writer did not complete its refusal")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || server.acceptedConnections() != connections {
		t.Fatal("refused legacy writer changed ciphertext or reached the SSH server")
	}
}
