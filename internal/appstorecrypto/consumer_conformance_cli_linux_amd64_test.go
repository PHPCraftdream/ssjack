//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

// The consumer conformance kit drives an externally supplied consumer command
// through the real keeper grants, adapter, pinned transport and SSH target.
// docs/CONSUMER-CONFORMANCE.md defines the contract; this file owns the
// configuration surface and the consumer process runner.
const (
	consumerGate        = "SSJACK_CONSUMER_CONFORMANCE"
	consumerTextChild   = "SSJACK_CONSUMER_TEXT_CHILD"
	consumerStreamChild = "SSJACK_CONSUMER_STREAM_CHILD"

	consumerCommandEnv = "SSJACK_CONSUMER_COMMAND"
	consumerArgsEnv    = "SSJACK_CONSUMER_ARGS"
	consumerDeployEnv  = "SSJACK_CONSUMER_DEPLOY_NAME"
	consumerBackupEnv  = "SSJACK_CONSUMER_BACKUP_NAME"
	consumerWorkdirEnv = "SSJACK_CONSUMER_WORKDIR"
	consumerEnvEnv     = "SSJACK_CONSUMER_ENV"

	consumerProfile = "pair-target"
	pairLongSecret  = "pair-synthetic-key-long-v1"
	pairShortSecret = "pair-synthetic-key"
)

var (
	consumerConfigEnv   = []string{consumerCommandEnv, consumerArgsEnv, consumerDeployEnv, consumerBackupEnv, consumerWorkdirEnv, consumerEnvEnv}
	consumerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)
	consumerVarPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	consumerFixedEnv    = map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "LANG": true}
)

type consumerConfig struct {
	command string
	args    []string
	deploy  string
	backup  string
	workdir string
	env     []string
}

// loadConsumerConfig validates the SSJACK_CONSUMER_* settings and fails the
// test on any missing or malformed value; a requested kit never skips.
func loadConsumerConfig(t testing.TB) consumerConfig {
	t.Helper()
	config := consumerConfig{command: os.Getenv(consumerCommandEnv), deploy: "deploy-text", backup: "backup-text"}
	info, err := os.Stat(config.command)
	if !filepath.IsAbs(config.command) || err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s must name an absolute executable file reachable by the unprivileged user (%v)", consumerCommandEnv, err)
	}
	if raw := os.Getenv(consumerArgsEnv); raw != "" {
		if err := json.Unmarshal([]byte(raw), &config.args); err != nil {
			t.Fatalf("%s must be a JSON array of strings", consumerArgsEnv)
		}
	}
	for variable, target := range map[string]*string{consumerDeployEnv: &config.deploy, consumerBackupEnv: &config.backup} {
		if value := os.Getenv(variable); value != "" {
			if !consumerNamePattern.MatchString(value) {
				t.Fatalf("%s is not a valid subcommand name", variable)
			}
			*target = value
		}
	}
	if config.deploy == config.backup {
		t.Fatal("deploy and backup subcommand names must differ")
	}
	if config.workdir = os.Getenv(consumerWorkdirEnv); config.workdir != "" {
		info, err := os.Stat(config.workdir)
		if !filepath.IsAbs(config.workdir) || err != nil || !info.IsDir() {
			t.Fatalf("%s must name an absolute directory", consumerWorkdirEnv)
		}
	}
	if raw := os.Getenv(consumerEnvEnv); raw != "" {
		var extra map[string]string
		if err := json.Unmarshal([]byte(raw), &extra); err != nil {
			t.Fatalf("%s must be a JSON object of strings", consumerEnvEnv)
		}
		for name, value := range extra {
			if !consumerVarPattern.MatchString(name) || strings.HasPrefix(name, "SSJACK_") || consumerFixedEnv[name] {
				t.Fatalf("%s may not set %q", consumerEnvEnv, name)
			}
			config.env = append(config.env, name+"="+value)
		}
		sort.Strings(config.env)
	}
	return config
}

// consumerChildEnv is the minimal environment of the unprivileged test child;
// it forwards only the consumer configuration.
func consumerChildEnv(childVariable string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "TMPDIR=/tmp", consumerGate + "=1", childVariable + "=1"}
	for _, name := range consumerConfigEnv {
		if value := os.Getenv(name); value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}

type consumerCLI struct {
	config       consumerConfig
	root         string
	templatePath string
	backupPath   string
}

func newConsumerCLI(t *testing.T, template string) consumerCLI {
	t.Helper()
	root := t.TempDir()
	cli := consumerCLI{config: loadConsumerConfig(t), root: root, templatePath: filepath.Join(root, "template.txt"), backupPath: filepath.Join(root, "backup.txt")}
	if err := os.WriteFile(cli.templatePath, []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}
	return cli
}

func (cli consumerCLI) deploy(t *testing.T, bootstrap *apptransport.Bootstrap, wantStatus string, success bool, args ...string) {
	t.Helper()
	cli.run(t, bootstrap, wantStatus, success, cli.config.deploy, args...)
}

func (cli consumerCLI) backup(t *testing.T, bootstrap *apptransport.Bootstrap, wantStatus string, success bool, args ...string) {
	t.Helper()
	cli.run(t, bootstrap, wantStatus, success, cli.config.backup, args...)
}

// run executes the consumer once. With a bootstrap the consumer receives the
// launcher environment; without one it must refuse. wantStatus, when set,
// must appear as exactly one {"status":...} object on the output.
func (cli consumerCLI) run(t *testing.T, bootstrap *apptransport.Bootstrap, wantStatus string, success bool, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	argv := append(append(append([]string(nil), cli.config.args...), name), args...)
	command := exec.CommandContext(ctx, cli.config.command, argv...)
	command.Dir = cli.root
	if cli.config.workdir != "" {
		command.Dir = cli.config.workdir
	}
	command.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + cli.root, "TMPDIR=/tmp", "LANG=C.UTF-8"}, cli.config.env...)
	if bootstrap != nil {
		command.Env = append(command.Env, "SSJACK_TEXT_LAUNCH=1", "SSJACK_TEXT_PROFILE="+consumerProfile, apptransport.EnvEndpoint+"="+bootstrap.Endpoint, apptransport.EnvToken+"="+bootstrap.Token, apptransport.EnvPin+"="+bootstrap.Pin)
	}
	log := &boundedChildLog{}
	command.Stdout, command.Stderr = log, log
	err := command.Run()
	output := log.String()
	if bytes.Contains([]byte(output), []byte(pairShortSecret)) || log.truncated {
		t.Fatal("consumer output disclosed private data or exceeded diagnostic bounds")
	}
	if ctx.Err() != nil || (err == nil) != success {
		t.Fatalf("consumer completion mismatch: success=%t error=%v\n%s", success, err, output)
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
		t.Fatalf("consumer did not emit exactly one expected status\n%s", output)
	}
}

func consumerServer(t *testing.T, installation *appstorecrypto.Installation, grant declarativeauthority.TextAdapterGrant, runner remote.StreamRunner) apptransport.Bootstrap {
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
		t.Fatalf("construct approved adapter: %v", err)
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

func consumerAssertFile(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != expected {
		t.Fatal("selected file differs from exact expected bytes")
	}
}

func consumerAssertOperatorFiles(t *testing.T, root string) {
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
