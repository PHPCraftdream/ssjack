package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/broker"
)

func TestHelpAndMissingCommand(t *testing.T) {
	if code, err := run(context.Background(), []string{"-help"}); code != 0 || err != nil {
		t.Fatalf("help: %d %v", code, err)
	}
	if code, err := run(context.Background(), nil); code == 0 || err == nil {
		t.Fatal("missing harness was accepted")
	}
}

func TestMCPRequiresSession(t *testing.T) {
	t.Setenv(broker.EnvFile, "")
	t.Setenv(broker.EnvToken, "")
	if code, err := run(context.Background(), []string{"mcp"}); code == 0 || err == nil {
		t.Fatal("MCP started without a session")
	}
	if code, err := run(context.Background(), []string{"mcp", "extra"}); code == 0 || err == nil {
		t.Fatal("invalid MCP arguments were accepted")
	}
}

func TestHarnessTailIsNotParsedAsSSJackFlags(t *testing.T) {
	dir := t.TempDir()
	file, err := os.CreateTemp(dir, "input")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	previous := os.Stdin
	os.Stdin = file
	defer func() { os.Stdin = previous }()
	for _, profileFlag := range []string{"-p", "--profile"} {
		args := []string{"--vault", filepath.Join(dir, "missing"), profileFlag, "main", "run", "claude", "-c"}
		code, err := run(context.Background(), args)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Fatalf("harness tail was parsed as local flags: %d %v", code, err)
		}
	}
}
