package help_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/help"
)

func TestHelpAndVersionNeverOpenVault(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.ssjack.ktav")
	for _, topic := range help.Topics() {
		args := []string{"--vault", missing, "help"}
		args = append(args, strings.Fields(topic)...)
		if code, err := cli.Run(context.Background(), args); code != 0 || err != nil {
			t.Fatalf("authenticated help or invalid routing for %s: %d %v", topic, code, err)
		}
	}
	if code, err := cli.Run(context.Background(), []string{"--vault", missing, "--version"}); code != 0 || err != nil {
		t.Fatalf("version tried to open credentials: %d %v", code, err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("informational commands created credentials")
	}
}
