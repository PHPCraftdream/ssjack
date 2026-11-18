package clitest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
)

func TestRemovedDirectoryMigrationRefusesBeforeCredentialInput(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
	original := []byte("synthetic ciphertext sentinel")
	if err := os.WriteFile(source, original, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tail := range [][]string{{"vault", "migrate-directory", destination}, {"help", "vault", "migrate-directory"}} {
		args := append([]string{"--vault", source}, tail...)
		code, err := cli.Run(context.Background(), args)
		if code != 1 || err == nil || strings.Contains(err.Error(), "interactive terminal") {
			t.Fatalf("removed command did not refuse as invalid syntax: %d %v", code, err)
		}
	}
	got, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("removed command changed the source")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "source" {
		t.Fatal("removed command created output or staging files")
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
		code, err := cli.Run(context.Background(), command)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Fatalf("command bypassed interactive input: %v: %d %v", args, code, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "vault")); !os.IsNotExist(err) {
		t.Fatal("vault was created without interactive confirmation")
	}
}

func TestAppstoreCommandRoutingAndUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no operation", nil, "usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]"},
		{"setup arity", []string{"setup"}, "usage: ssjack appstore setup DIR"},
		{"setup extra argument", []string{"setup", "dir", "extra"}, "usage: ssjack appstore setup DIR"},
		{"put arity", []string{"put"}, "usage: ssjack appstore put DIR"},
		{"put extra argument", []string{"put", "dir", "extra"}, "usage: ssjack appstore put DIR"},
		{"inspect arity", []string{"inspect"}, "usage: ssjack appstore inspect DIR"},
		{"inspect extra argument", []string{"inspect", "dir", "extra"}, "usage: ssjack appstore inspect DIR"},
		{"unlock arity", []string{"unlock"}, "usage: ssjack appstore unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]"},
		{"unknown operation", []string{"unknown"}, "usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, err := cli.Run(context.Background(), append([]string{"appstore"}, tc.args...))
			if code == 0 || err == nil || err.Error() != tc.want {
				t.Fatalf("cli.Run appstore %v = %d, %v; want usage %q", tc.args, code, err, tc.want)
			}
		})
	}
}
