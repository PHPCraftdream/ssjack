package launch

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/hooks"
	"github.com/PHPCraftdream/ssjack/internal/uiplugin"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestHarnessProcess(t *testing.T) {
	if os.Getenv("SSJACK_TEST_HELPER") != "1" {
		return
	}
	if len(os.Getenv(broker.EnvToken)) != 64 || os.Getenv(broker.EnvEndpoint) == "" || os.Getenv(broker.EnvFile) != "" {
		os.Exit(90)
	}
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "arg with spaces" || os.Args[len(os.Args)-1] != "--flag=value" {
		os.Exit(93)
	}
	directories := filepath.SplitList(os.Getenv(uiplugin.EnvDirectories))
	if len(directories) < 2 || directories[0] != "parent-plugin" {
		os.Exit(94)
	}
	if _, err := os.Stat(filepath.Join(directories[len(directories)-1], ".claude-plugin", "plugin.json")); err != nil {
		os.Exit(95)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := broker.ConnectBootstrap(ctx, broker.Bootstrap{Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint), Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken)})
	if err != nil {
		os.Exit(91)
	}
	var response struct{ Value string }
	if err := client.Call(ctx, "test", struct{}{}, &response); err != nil || response.Value != "ok" {
		os.Exit(92)
	}
	client.Close()
	fmt.Println("attached")
	os.Exit(7)
}

func TestLaunchPassesOnlyChildCredentialsAndPreservesExit(t *testing.T) {
	t.Setenv("SSJACK_TEST_HELPER", "1")
	t.Setenv(broker.EnvToken, "parent-value")
	t.Setenv(broker.EnvFile, "stale-file")
	t.Setenv(uiplugin.EnvDirectories, "parent-plugin")
	root := t.TempDir()
	if err := hooks.Install(root, filepath.Join(root, "ssjack.exe")); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := Run(ctx, Options{
		Root: root, Executable: executable,
		Command: []string{executable, "-test.run=^TestHarnessProcess$", "--", "arg with spaces", "--flag=value"}, BootstrapTTL: time.Minute,
		Handler: func(context.Context, wire.Request) wire.Reply {
			return broker.Result(struct{ Value string }{"ok"}, nil)
		},
		Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil || code != 7 || strings.TrimSpace(stdout.String()) != "attached" {
		t.Fatalf("harness: %d %v %q %q", code, err, stdout.String(), stderr.String())
	}
	if os.Getenv(broker.EnvFile) != "stale-file" || os.Getenv(broker.EnvToken) != "parent-value" || os.Getenv(uiplugin.EnvDirectories) != "parent-plugin" {
		t.Fatal("parent environment was changed")
	}
	localSettings, err := os.ReadFile(filepath.Join(root, ".claude", "settings.local.json"))
	if err != nil || bytes.Contains(localSettings, []byte("PreToolUse")) {
		t.Fatal("obsolete display hooks were not removed at startup")
	}
	if _, err := os.Stat(filepath.Join(root, ".ssh", "runtime")); !os.IsNotExist(err) {
		t.Fatal("memory-only bootstrap created a runtime directory")
	}
	data, err := os.ReadFile(filepath.Join(root, ".mcp.json"))
	if err != nil || strings.Contains(string(data), "token") || strings.Contains(string(data), "parent-value") {
		t.Fatal("configuration must not contain secrets")
	}
}

func TestExistingMCPIsNotOverwritten(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".mcp.json")
	original := []byte(`{"mcpServers":{"other":{"command":"other"}}}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureMCP(root); err == nil {
		t.Fatal("missing entry must require manual insertion")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("existing .mcp.json was changed")
	}
	root = t.TempDir()
	if err := EnsureMCP(root); err != nil {
		t.Fatal(err)
	}
	if err := EnsureMCP(root); err != nil {
		t.Fatal("rechecking a valid entry must be idempotent")
	}
}

func TestEnvironmentAndFailedLaunchCleanup(t *testing.T) {
	env := Environment([]string{"PATH=original", "ssjack_env_token=stale", "SSJACK_BOOTSTRAP_FILE=stale", "ssjack_session=stale", "SSJACK_ENDPOINT=stale", "SSJACK_CERTIFICATE_SHA256=stale", "KEEP=value"}, broker.Bootstrap{Token: "new", Session: "session", Endpoint: "endpoint", Pin: "pin"}, filepath.Join("bin", "ssjack"))
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "stale") || strings.Contains(joined, broker.EnvFile+"=") || !strings.Contains(joined, "KEEP=value") || !strings.Contains(joined, "SSJACK_ENV_TOKEN=new") {
		t.Fatal("incorrect environment")
	}
	root := t.TempDir()
	_, err := Run(context.Background(), Options{
		Root: root, Executable: "ssjack", Command: []string{filepath.Join(root, "missing-harness")}, BootstrapTTL: time.Minute,
		Handler: func(context.Context, wire.Request) wire.Reply { return wire.Reply{OK: true} },
	})
	if err == nil {
		t.Fatal("nonexistent harness was started")
	}
	if _, err := os.Stat(filepath.Join(root, ".ssh", "runtime")); !os.IsNotExist(err) {
		t.Fatal("failed launch created a runtime directory")
	}
}
