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

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// ownerImportTerminalAcceptance drives the real interactive owner editor in a
// terminal (tmux) against a truly empty destination: wrong archive password,
// cancelled preview, then a confirmed import. The reopened database proves
// the result through the real backend.
func ownerImportTerminalAcceptance(t *testing.T, ctx context.Context, storeDirectory, master string, exportPassword []byte, fixture importFixture, original *vault.Vault) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatal("owner import terminal acceptance requires the Linux CI fixture")
	}
	password := []byte("synthetic destination C database password")
	defer clear(password)
	manager, path := openImportDestination(t, ctx, storeDirectory, master, password, "")
	defer manager.Discard()
	// Close releases the store lock and persists the link; the child unlocks alone.
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	runImportTerminal(t, ctx, path, password, exportPassword, fixture)

	reopened, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Discard()
	verifyTerminalImport(t, ctx, reopened, fixture, original)
	if err := reopened.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if importDigest(t, fixture.plaintext) != fixture.plaintextDigest || importDigest(t, fixture.encrypted) != fixture.encryptedDigest {
		t.Fatal("terminal owner import changed a source archive")
	}
}

// runImportTerminal passes every secret on stdin, never on the command line.
func runImportTerminal(t *testing.T, ctx context.Context, database string, password, exportPassword []byte, fixture importFixture) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_import.py"))
	if err != nil {
		t.Fatal(err)
	}
	var input []byte
	defer func() { clear(input) }()
	for _, line := range append([][]byte{password, []byte(importWrongPassword), exportPassword}, leakLines(fixture.leaks)...) {
		input = append(append(input, line...), '\n')
	}
	command := exec.CommandContext(ctx, "python3", "-I", driver, executable, database, fixture.encrypted)
	command.Stdin = bytes.NewReader(input)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("synthetic owner import terminal interaction: %v: %s", err, output)
	}
}

func leakLines(leaks []string) [][]byte {
	lines := make([][]byte, 0, len(leaks))
	for _, leak := range leaks {
		if leak != "" {
			lines = append(lines, []byte(leak))
		}
	}
	return lines
}

// verifyTerminalImport exports the reopened destination in plaintext, which
// reads every imported value back from its published reference.
func verifyTerminalImport(t *testing.T, ctx context.Context, manager *ownerdb.Manager, fixture importFixture, original *vault.Vault) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "terminal-destination-export.zip")
	selection := vault.ExportSelection{Servers: map[string][]string{fixture.server: {"main", "second"}}, GlobalSecrets: true}
	if err := manager.Export(ownerdb.ExportRequest{Selection: selection, Destination: path, PlaintextConfirmation: "EXPORT PLAINTEXT"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	opened, err := ownerarchive.ReadFile(ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	var selected vault.Vault
	if err := pure.LoadsInto(string(opened.Database()), &selected); err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	source, imported := original.Servers[fixture.server], selected.Servers[fixture.server]
	if len(selected.Servers) != 1 || len(selected.Targets) != 2 || imported.Name != source.Name || len(imported.Accounts) != 2 {
		t.Fatal("terminal import did not create exactly the imported server")
	}
	for name, profile := range source.Accounts {
		got, exists := imported.Accounts[name]
		if !exists || !sameTarget(original.Targets[profile], selected.Targets[got]) {
			t.Fatal("terminal import changed an account identity or credential")
		}
	}
	if len(selected.Secrets) != len(fixture.secrets) || opened.Encrypted() || len(opened.SecretIDs()) != len(fixture.values) {
		t.Fatal("terminal import has an unexpected secret inventory")
	}
	for id, want := range fixture.secrets {
		got, exists := selected.Secrets[id]
		if !exists || got.Name != want.Name || got.ServerID != want.ServerID || got.Ref == want.Ref {
			t.Fatal("terminal import lost an alias identity, scope or fresh reference")
		}
	}
	for id, want := range fixture.values {
		if value, exists := opened.Value(id); !exists || !bytes.Equal(value, want) {
			t.Fatal("terminal imported value differs from the exported value")
		}
	}
}
