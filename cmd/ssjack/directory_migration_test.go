package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryMigrationRoutingStopsBeforeCredentialInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := filepath.Join(t.TempDir(), "missing-source")
	destination := source + "-new"
	code, err := runVaultMaintenance(ctx, source, "main", []string{"migrate-directory", destination})
	if code != 1 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled migration did not reach the dedicated command")
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatal("cancelled migration created a source database")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("cancelled migration created output")
	}
	if err := os.WriteFile(destination, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	code, err = runVaultMaintenance(context.Background(), source, "main", []string{"migrate-directory", destination})
	if code != 1 || err == nil {
		t.Fatal("migration did not reject existing output before prompting")
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != "existing" {
		t.Fatal("refused migration modified existing output")
	}
}
