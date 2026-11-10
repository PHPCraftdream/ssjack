package mcpstart_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestLaunchOutputSetupFailurePrecedesFilesystemAndHarness(t *testing.T) {
	root := t.TempDir()
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "harness-ran")
	const privateLiteral = "synthetic-bootstrap-setup-secret"
	code, runErr := launch.Run(context.Background(), launch.Options{
		Root: root, Mode: broker.ModeFull, Executable: "ssjack",
		Command: []string{"missing-harness", marker}, BootstrapTTL: time.Minute,
		Handler:       func(context.Context, wire.Request) wire.Reply { return wire.Reply{} },
		PrepareOutput: func(*outputguard.Snapshot) error { return errors.New(privateLiteral) },
	})
	if code != 1 || runErr == nil || runErr.Error() != "MCP bootstrap output guard setup failed" || strings.Contains(runErr.Error(), privateLiteral) {
		t.Fatalf("setup failure was not fixed and sanitized: code=%d error=%v", code, runErr)
	}
	after, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed output setup changed the root directory")
	}
	for _, path := range []string{
		filepath.Join(root, ".mcp.json"), filepath.Join(root, ".claude"),
		filepath.Join(root, ".ssh"), marker,
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("failed output setup created %s", filepath.Base(path))
		}
	}
}
