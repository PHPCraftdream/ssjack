package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		code, err := run(context.Background(), args)
		if code != 1 || err == nil || strings.Contains(err.Error(), "interactive terminal") {
			t.Fatalf("removed command did not refuse as invalid syntax: %d %v", code, err)
		}
	}
	if findHelp("vault migrate-directory") != nil {
		t.Fatal("removed command remains advertised")
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
