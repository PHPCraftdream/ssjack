//go:build linux

package transfertest

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/remotemcp"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/childdiag"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/sshfixture"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/transferacceptance"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const (
	transferKeeperGate  = "SSJACK_TRANSFER_FULLPROFILE_KEEPER"
	transferHarnessGate = "SSJACK_TRANSFER_FULLPROFILE_HARNESS"
	transferBridgeGate  = "SSJACK_TRANSFER_FULLPROFILE_BRIDGE"
	transferRootEnv     = "SSJACK_TRANSFER_FULLPROFILE_ROOT"
	transferSandboxEnv  = "SSJACK_TRANSFER_FULLPROFILE_SANDBOX"
	transferObserved    = "TRANSFER-FULLPROFILE-OBSERVED:"
	transferSecret      = "SYNTHETIC-TRANSFER-PAYLOAD-fullprofile-2c7b41e9"
)

// TestVaultTransferKeeperChild is the real ssjack keeper: it runs the
// production run command with a registered transfer root and the synthetic
// SSH fixture as its approved target.
func TestVaultTransferKeeperChild(t *testing.T) {
	if os.Getenv(transferKeeperGate) != "1" {
		t.Skip("transfer full-profile keeper child only")
	}
	var args []string
	for index, argument := range os.Args {
		if argument == "--" {
			args = os.Args[index+1:]
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	started := time.Now()
	flakediag.OnFailure(t, func() string {
		return "transfer keeper child: args=" + fmt.Sprint(len(args)) +
			" elapsed=" + time.Since(started).Round(time.Millisecond).String() +
			"\ngoroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
	code, err := cli.Run(ctx, args)
	if err != nil || code != 0 {
		t.Fatalf("transfer keeper did not finish cleanly: code=%d err=%v", code, err)
	}
}

// TestVaultTransferBridgeChild is the production launcher harness: it
// attaches a real MCP client to the real stdio bridge process and drives
// the four transfer tools.
func TestVaultTransferBridgeChild(t *testing.T) {
	if os.Getenv(transferHarnessGate) != "1" {
		t.Skip("transfer full-profile harness child only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestVaultTransferMCPBridgeChild$")
	command.Env = append(os.Environ(), transferBridgeGate+"=1")
	command.Stderr = os.Stderr
	// Failure-only evidence for the real stdio bridge child; its output
	// already flows to the harness stderr.
	childdiag.ProcessOnFailure(t, "transfer bridge child", command, nil, time.Now())
	client := mcp.NewClient(&mcp.Implementation{Name: "transfer-full-profile-harness", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal("harness could not attach to the real stdio MCP bridge")
	}
	root, sandbox := os.Getenv(transferRootEnv), os.Getenv(transferSandboxEnv)
	if root == "" || sandbox == "" {
		t.Fatal("harness did not receive its fixture locations")
	}
	transferHarnessScenario(t, ctx, session, root, sandbox)
	if err := session.Close(); err != nil {
		t.Fatal("real stdio bridge session did not close cleanly")
	}
	fmt.Fprintln(os.Stderr, transferObserved+"keeper-mcp-roundtrip")
}

// TestVaultTransferMCPBridgeChild is the real production stdio bridge.
func TestVaultTransferMCPBridgeChild(t *testing.T) {
	if os.Getenv(transferBridgeGate) != "1" {
		t.Skip("transfer full-profile bridge child only")
	}
	code, err := remotemcp.Run(context.Background())
	if err != nil || code != 0 {
		t.Fatalf("real MCP bridge failed: code=%d err=%v", code, err)
	}
}

// TestVaultTransferFullProfile proves the real keeper end to end: a vault
// created with the production KDF, --transfer-root startup, the real stdio
// MCP bridge over the broker, the four transfer tools against a synthetic
// SSH server that really executes commands, byte-exact round trips, and
// both refusal observations.
func TestVaultTransferFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("transfer full-profile acceptance runs in GitHub CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	root, sandbox, keeperDir := transferDir(t), transferDir(t), transferDir(t)
	fixture := transferacceptance.StartExecServer(t, sandbox, nil)
	fixture.SetPassword(sshfixture.ConnectPassword)
	notes := append([]byte(transferSecret), transferacceptance.SeedPayload(96*1024, 21)...)
	transferacceptance.WriteTree(t, root, map[string][]byte{"in/notes.txt": notes}, []string{"in"})
	transferacceptance.WriteTree(t, sandbox, map[string][]byte{
		"tree/report.txt":    []byte("synthetic remote tree"),
		"tree/data/blob.bin": transferacceptance.SeedPayload(64*1024, 22),
	}, []string{"in", "tree", "tree/data"})
	directory := vault.NewDirectory()
	defer directory.Close()
	target := vault.Target{
		Address:  fixture.Address(),
		User:     "transfer-user",
		Password: []byte(sshfixture.ConnectPassword),
		HostKeys: []string{string(ssh.MarshalAuthorizedKey(fixture.HostKey()))},
		Usage:    "agent",
	}
	defer clear(target.Password)
	if _, err := directory.AddServer("production", "main", target); err != nil {
		t.Fatal(err)
	}
	password := []byte("synthetic transfer full-profile database password")
	defer clear(password)
	vaultPath := filepath.Join(transferDir(t), "transfer.ktav")
	if err := vault.CreateWithRecords(ctx, vaultPath, directory, password); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	keeper := exec.CommandContext(ctx, executable,
		"-test.run=^TestVaultTransferKeeperChild$", "--",
		"--vault", vaultPath, "--server", "production", "--account", "main",
		"--transfer-root", root, "run", executable, "-test.run=^TestVaultTransferBridgeChild$")
	keeper.Dir = keeperDir
	keeper.Env = transferKeeperEnvironment(password, root, sandbox)
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	keeper.Stdout, keeper.Stderr = stdout, stderr
	keeperStarted := time.Now()
	if err := keeper.Start(); err != nil {
		t.Fatal(err)
	}
	childdiag.ProcessOnFailure(t, "transfer keeper process", keeper, nil, keeperStarted)
	if err := keeper.Wait(); err != nil {
		t.Fatalf("keeper or harness did not finish: %v\nstdout tail:%s\nstderr tail:%s",
			err, flakediag.Tail(stdout.String(), 16*1024), flakediag.Tail(stderr.String(), 16*1024))
	}
	transferVerifyOutput(t, stdout, stderr, password)
	t.Logf("keeper output: %q / %q", stdout.String(), stderr.String())
	transferVerifyDisk(t, root, sandbox, notes)
	for _, marker := range []string{"upload", "download", "refused-path", "unregistered-root", "keeper-mcp-roundtrip"} {
		line := transferObserved + marker
		if !bytes.Contains(stdout.Bytes(), []byte(line)) && !bytes.Contains(stderr.Bytes(), []byte(line)) {
			t.Fatalf("transfer harness did not report %s\nstdout tail:%s\nstderr tail:%s", line,
				flakediag.Tail(stdout.String(), 16*1024), flakediag.Tail(stderr.String(), 16*1024))
		}
		t.Log(line)
	}
}

func transferKeeperEnvironment(password []byte, root, sandbox string) []string {
	environment := make([]string, 0, len(os.Environ())+6)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "SSJACK_VAULT_PASSWORD", transferKeeperGate, transferHarnessGate, transferBridgeGate:
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment,
		"SSJACK_VAULT_PASSWORD="+string(password),
		transferKeeperGate+"=1",
		transferHarnessGate+"=1",
		transferRootEnv+"="+root,
		transferSandboxEnv+"="+sandbox,
	)
}

// transferVerifyOutput scans every byte the keeper and harness wrote: the
// vault password, the SSH credential and the file content must never appear.
func transferVerifyOutput(t *testing.T, stdout, stderr *bytes.Buffer, password []byte) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(transferSecret))
	for _, buffer := range [][]byte{stdout.Bytes(), stderr.Bytes()} {
		for _, secret := range []string{string(password), sshfixture.ConnectPassword, transferSecret, encoded} {
			if bytes.Contains(buffer, []byte(secret)) {
				t.Fatal("keeper output disclosed secret material")
			}
		}
	}
}

// transferVerifyDisk checks byte-exact round trips and refusal side effects
// directly on disk.
func transferVerifyDisk(t *testing.T, root, sandbox string, notes []byte) {
	t.Helper()
	stored, err := os.ReadFile(filepath.Join(sandbox, "in", "notes.txt"))
	if err != nil || !bytes.Equal(stored, notes) {
		t.Fatalf("uploaded file is not byte-exact: %v", err)
	}
	source, err := os.ReadFile(filepath.Join(root, "in", "notes.txt"))
	if err != nil || !bytes.Equal(source, notes) {
		t.Fatal("upload modified its source")
	}
	transferacceptance.CompareTrees(t, filepath.Join(sandbox, "tree"), filepath.Join(root, "returned"))
	if _, err := os.Stat(filepath.Join(sandbox, "in", "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("traversal attempt published a destination")
	}
	if _, err := os.Stat(filepath.Join(root, "denied")); !os.IsNotExist(err) {
		t.Fatal("unregistered root attempt published a destination")
	}
	transferacceptance.AssertNoStaging(t, root)
	transferacceptance.AssertNoStaging(t, sandbox)
}

func transferDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
