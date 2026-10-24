package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"storagehost/internal/broker"
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
	missing := filepath.Join(t.TempDir(), "missing.ktav")
	code, err := run(context.Background(), []string{"--config", missing, "claude", "-c"})
	if code == 0 || !os.IsNotExist(err) {
		t.Fatalf("-c must belong to the harness rather than ssjack: %d %v", code, err)
	}
}
