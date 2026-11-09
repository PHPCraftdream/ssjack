package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
)

func TestOwnerSyntaxAndSecretFlagsRefuseBeforeUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.ssjack.ktav")
	for _, tail := range [][]string{
		{"owner"}, {"owner", "unknown"},
		{"owner", "add-server", "--password", "synthetic-input-secret"},
		{"owner", "add-secret", "--scope", "global", "--value", "synthetic-input-secret"},
		{"owner", "import", "--archive-password", "synthetic-input-secret"},
		{"owner", "remove-secret", "--scope", "global", "--secret", "token", "--yes"},
		{"owner", "edit-account", "--server", "production"},
		{"--profile", "main", "owner", "add-server"},
	} {
		code, err := run(context.Background(), append([]string{"--vault", path}, tail...))
		if code != 1 || !errors.Is(err, ownercommand.ErrArguments) || strings.Contains(err.Error(), "synthetic-input-secret") {
			t.Fatal("owner syntax read credentials or exposed arguments")
		}
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("owner syntax created a database")
	}
}

func TestEveryOwnerCommandHasNoUnlockHelp(t *testing.T) {
	for _, entry := range ownerHelpEntries() {
		if findHelp(entry.Name) == nil {
			t.Fatalf("unregistered owner help: %s", entry.Name)
		}
		if code, err := run(context.Background(), append([]string{"help"}, strings.Fields(entry.Name)...)); code != 0 || err != nil {
			t.Fatal("owner help tried to unlock")
		}
	}
}
