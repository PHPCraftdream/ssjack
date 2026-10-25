package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestCancelledVaultUpgradeDoesNotPrompt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, err := runVaultMaintenance(ctx, filepath.Join(t.TempDir(), "missing"), "main", []string{"upgrade"})
	if code == 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("upgrade did not stop before terminal authorization: %d %v", code, err)
	}
}
