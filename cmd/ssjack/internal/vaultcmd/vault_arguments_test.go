package vaultcmd_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/vaultcmd"
)

func TestVaultArguments(t *testing.T) {
	for _, args := range [][]string{{"init"}, {"list"}, {"passwd"}, {"add", "target"}, {"edit", "target"}, {"show", "target"}, {"remove", "target"}, {"public", "target"}, {"import", "target", "input"}, {"export", "target", "output"}} {
		if err := vaultcmd.ValidateVaultArgs(args); err != nil {
			t.Fatalf("valid arguments %v: %v", args, err)
		}
	}
	for _, args := range [][]string{nil, {"unknown"}, {"list", "extra"}, {"show"}, {"add", "../name"}, {"remove", "target", "extra"}, {"import", "target"}, {"export", "target", ""}} {
		if err := vaultcmd.ValidateVaultArgs(args); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
	for _, args := range [][]string{
		{"ssh", "target", "vault", "list"},
		{"--generate-key", "key", "ssh", "target"},
		{"ssh", "../target"},
		{"vault", "unknown"},
	} {
		if code, err := cli.Run(context.Background(), args); code == 0 || err == nil {
			t.Fatalf("invalid mode combination accepted: %v", args)
		}
	}
}

func TestGeneratedProfileSyntaxAndCancellation(t *testing.T) {
	for _, args := range [][]string{{"add", "work", "--generate-key"}, {"add", "work"}} {
		if err := vaultcmd.ValidateVaultArgs(args); err != nil {
			t.Fatalf("valid generation syntax: %v", err)
		}
	}
	for _, args := range [][]string{{"edit", "work", "--generate-key"}, {"add", "work", "--unknown"}, {"add", "work", "--generate-key", "extra"}} {
		if err := vaultcmd.ValidateVaultArgs(args); err == nil {
			t.Fatal("invalid generation syntax accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{{"-p", "work", "add", "--generate-key"}, {"-p", "work", "vault", "init", "--generate-key"}} {
		code, err := cli.Run(ctx, args)
		if code == 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled generation prompted or saved: %v", err)
		}
	}
}
