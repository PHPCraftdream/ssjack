//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const (
	pairGate        = "SSJACK_CLAWWRIGHT_PAIR_CI"
	pairChild       = "SSJACK_CLAWWRIGHT_PAIR_CHILD"
	pairRoot        = "SSJACK_CLAWWRIGHT_PAIR_ROOT"
	pairLongSecret  = "pair-synthetic-key-long-v1"
	pairShortSecret = "pair-synthetic-key"
)

type pairCLI struct {
	entry    string
	root     string
	apps     string
	app      string
	template string
	backup   string
}

func newPairCLI(t *testing.T, template string) pairCLI {
	t.Helper()
	clawRoot := os.Getenv(pairRoot)
	if !filepath.IsAbs(clawRoot) {
		t.Fatal("pair acceptance requires an absolute pinned checkout")
	}
	root := t.TempDir()
	apps := filepath.Join(root, "apps")
	app := filepath.Join(apps, "pair")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	module := func(path string) string {
		return (&url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(clawRoot, "packages", "clawwright", path))}).String()
	}
	declaration := fmt.Sprintf("import { defineApp } from %q;\nimport { openclawCommands } from %q;\nexport default defineApp({ name: 'pair', description: 'Synthetic text pair acceptance', commands: openclawCommands });\n", module("core/app.ts"), module("commands/interface/index.ts"))
	if err := os.WriteFile(filepath.Join(app, "app.ts"), []byte(declaration), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "package.json"), []byte("{\"type\":\"module\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cli := pairCLI{entry: filepath.Join(clawRoot, "tools", "clawwright.ts"), root: root, apps: apps, app: app, template: filepath.Join(root, "template.txt"), backup: filepath.Join(root, "backup.txt")}
	if err := os.WriteFile(cli.template, []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}
	return cli
}

func (cli pairCLI) run(t *testing.T, bootstrap *apptransport.Bootstrap, wantStatus string, success bool, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	argv := append([]string{cli.entry, "--app", "pair"}, args...)
	command := exec.CommandContext(ctx, "node", argv...)
	command.Dir = filepath.Dir(filepath.Dir(cli.entry))
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + cli.root, "TMPDIR=/tmp", "LANG=C.UTF-8", "NODE_NO_WARNINGS=1", "CLAWWRIGHT_CHECKS_APPS_DIR=" + cli.apps}
	if bootstrap != nil {
		command.Env = append(command.Env, "SSJACK_TEXT_LAUNCH=1", "SSJACK_TEXT_PROFILE=pair-target", "SSJACK_APP_ENDPOINT="+bootstrap.Endpoint, "SSJACK_APP_TOKEN="+bootstrap.Token, "SSJACK_APP_CERTIFICATE_SHA256="+bootstrap.Pin)
	}
	log := &boundedChildLog{}
	command.Stdout, command.Stderr = log, log
	err := command.Run()
	output := log.String()
	if bytes.Contains([]byte(output), []byte(pairShortSecret)) || log.truncated {
		t.Fatal("CLI output disclosed private data or exceeded diagnostic bounds")
	}
	if ctx.Err() != nil || (err == nil) != success {
		t.Fatalf("CLI completion mismatch: success=%t error=%v\n%s", success, err, output)
	}
	if wantStatus == "" {
		return
	}
	matches := 0
	for _, line := range strings.Split(output, "\n") {
		var result map[string]any
		if json.Unmarshal([]byte(line), &result) == nil && len(result) == 1 && result["status"] == wantStatus {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("CLI did not emit exactly one expected status\n%s", output)
	}
}

func pairServer(t *testing.T, installation *appstorecrypto.Installation, grant declarativeauthority.TextAdapterGrant, runner remote.StreamRunner) apptransport.Bootstrap {
	t.Helper()
	ctx := context.Background()
	var adapter *appstorecrypto.TextAdapter
	var err error
	if grant.Mode == "reverse-copy-v1" {
		adapter, err = appstorecrypto.NewReverseTextAdapter(ctx, installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
	} else {
		adapter, err = appstorecrypto.NewTextAdapter(ctx, installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
	}
	if err != nil {
		t.Fatalf("construct approved pair adapter: %v", err)
	}
	var server *apptransport.Server
	if grant.Mode == "reverse-copy-v1" {
		server, err = apptransport.ListenWithReverseTextAdapter(ctx, grant.Profile, runner, adapter)
	} else {
		server, err = apptransport.ListenWithTextAdapter(ctx, grant.Profile, runner, adapter)
	}
	if err != nil {
		_ = adapter.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		_ = adapter.Close()
	})
	return server.Bootstrap()
}

func pairAssertFile(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != expected {
		t.Fatal("selected file differs from exact expected bytes")
	}
}

func pairAssertOperatorFiles(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(pairShortSecret)) {
			t.Error("operator artifact contains hydrated data")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
