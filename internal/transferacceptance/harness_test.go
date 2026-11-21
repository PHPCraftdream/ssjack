//go:build linux || darwin

package transferacceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	chunks "github.com/PHPCraftdream/ssjack/internal/transferacceptance/internal/chunks"
	fixture "github.com/PHPCraftdream/ssjack/internal/transferacceptance/internal/fixture"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/wire"

	"golang.org/x/crypto/ssh"
)

// init injects the root harness sandbox environment into the chunks
// scenario package.
func init() {
	chunks.SandboxEnv = sandboxEnv
}

// treeState captures the files and directories of a fixture tree so a later
// assertTreeSnapshot can prove nothing changed. It delegates to the fixture
// package helper.
func treeState(t *testing.T, base string) (map[string][]byte, []string) {
	t.Helper()
	return fixture.TreeState(t, base)
}

const (
	targetName = "fixture-target"
	waitBudget = fixture.WaitBudget
)

// stack is one complete in-process installation: an SSH fixture with a real
// exec handler, a transfer root, the manager, a broker keeper, the real MCP
// bridge server and an MCP client session attached over in-memory
// transports.
type stack struct {
	ctx     context.Context
	root    *transferlocal.Root
	rootDir string
	sandbox string
	server  *ExecServer
	manager *transfer.Manager
	session *mcp.ClientSession
}

// newStack builds a stack with one unnamed transfer root.
func newStack(t *testing.T, limits transfercore.Limits, env []string) *stack {
	return newStackRoots(t, limits, env, true)
}

// sandboxEnv returns the environment used by the exec fixture. Explicit
// scenario environments take precedence; otherwise BusyBox CI gets its
// restricted applet PATH, while macOS uses only its stock system tools.
func sandboxEnv(t *testing.T, env []string) []string {
	t.Helper()
	if env != nil {
		return env
	}
	if dir := os.Getenv("SSJACK_TRANSFER_BUSYBOX_BIN"); dir != "" {
		shell := filepath.Join(dir, "sh")
		if _, err := os.Stat(shell); err != nil {
			t.Fatalf("busybox shell %s is missing: %v", shell, err)
		}
		return []string{"PATH=" + dir, "SSJACK_REMOTE_SHELL=" + shell}
	}
	if runtime.GOOS == "darwin" {
		return []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "SSJACK_REMOTE_SHELL=/bin/sh"}
	}
	return nil
}

// newStackRoots builds a stack; withRoots=false registers no transfer root,
// so every operation must fail closed.
func newStackRoots(t *testing.T, limits transfercore.Limits, env []string, withRoots bool) *stack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rootDir, sandbox := evalDir(t), evalDir(t)
	server := StartExecServer(t, sandbox, sandboxEnv(t, env))
	// Register after setup's closers so diagnostics run before any joins.
	defer server.RegisterFailureDiagnostics(t)
	config := &ssh.ClientConfig{
		User:            "acceptance",
		Auth:            []ssh.AuthMethod{sshauth.PublicKey(server.ClientSigner())},
		HostKeyCallback: ssh.FixedHostKey(server.HostKey()),
		Timeout:         5 * time.Second,
	}
	runner, err := remote.NewCredentialStreamRunner(targetName, server.Address(), config)
	if err != nil {
		t.Fatal(err)
	}
	var root *transferlocal.Root
	var roots []*transferlocal.Root
	if withRoots {
		parsed, err := transferlocal.ParseRoot(rootDir, "")
		if err != nil {
			t.Fatal(err)
		}
		root = parsed
		roots = append(roots, parsed)
	}
	manager, err := transfer.NewManager(roots, []string{targetName}, limits, func(target string) (transfer.Engine, error) {
		return transfer.NewEngine(runner, target, limits)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	session := connectBridge(t, ctx, manager)
	return &stack{
		ctx: ctx, root: root, rootDir: rootDir, sandbox: sandbox,
		server: server, manager: manager, session: session,
	}
}

// connectBridge starts a broker keeper over the manager and attaches an MCP
// client session through the real bridge server.
func connectBridge(t *testing.T, ctx context.Context, manager *transfer.Manager) *mcp.ClientSession {
	t.Helper()
	sessionToken, err := wire.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	keeperToken, err := wire.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	handler := func(ctx context.Context, request wire.Request) wire.Reply {
		reply, handled := manager.Handle(ctx, request)
		if !handled {
			return wire.Reply{Error: "unhandled keeper operation"}
		}
		return reply
	}
	keeper, err := broker.Listen(ctx, sessionToken, keeperToken, 10*time.Minute, handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keeper.Close)
	auth := wire.Auth{Version: 2, Session: sessionToken, Token: keeperToken}
	connection, err := broker.Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := bridge.NewServer(connection).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "transfer-acceptance", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	assertInventory(t, ctx, session)
	return session
}

func evalDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// mkdirAll creates a directory inside a fixture tree.
func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// assertInventory checks the bridge exposes the four transfer tools in a
// twelve-tool full-mode inventory.
func assertInventory(t *testing.T, ctx context.Context, session *mcp.ClientSession) {
	t.Helper()
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	listing, err := session.ListTools(deadline, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(listing.Tools))
	for _, tool := range listing.Tools {
		if tool != nil {
			names[tool.Name] = true
		}
	}
	for _, name := range []string{"remote_upload", "remote_download", "transfer_status", "transfer_cancel"} {
		if !names[name] {
			t.Fatalf("bridge inventory is missing %s", name)
		}
	}
	if len(listing.Tools) != 12 {
		t.Fatalf("full-mode bridge exposed %d tools, want 12", len(listing.Tools))
	}
}

// assertNoLeaks fails when any captured result carries one of the leak forms
// of a private payload: a raw prefix, base64, hex, or JSON-escaped text.
func assertNoLeaks(t *testing.T, c captured, payload []byte) {
	t.Helper()
	forms := leakForms(payload)
	for _, data := range c {
		for _, form := range forms {
			if bytes.Contains(data, []byte(form)) {
				t.Fatal("captured result matched a prohibited transfer representation")
			}
		}
	}
}

func leakForms(payload []byte) []string {
	if len(payload) > 32 {
		payload = payload[:32]
	}
	raw := string(payload)
	forms := []string{raw, base64.StdEncoding.EncodeToString(payload), hex.EncodeToString(payload)}
	if encoded, err := json.Marshal(raw); err == nil {
		if escaped := string(encoded[1 : len(encoded)-1]); escaped != raw {
			forms = append(forms, escaped)
		}
	}
	return forms
}

// assertSHA fails when a status digest does not match the bytes.
func assertSHA(t *testing.T, payload []byte, got string) {
	t.Helper()
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("status sha256 does not match transferred bytes: got len=%d short=%s, want len=%d short=%s", len(got), flakediag.Short([]byte(got)), len(want), flakediag.Short([]byte(want)))
	}
}

// runTransferScenario wraps a top-level scenario subtest so flakediag
// environment tracking (pass index, entry time) starts at real subtest
// entry, before any fixture diagnostics register their cleanups.
func runTransferScenario(t *testing.T, name string, scenario func(t *testing.T)) {
	t.Run(name, func(t *testing.T) {
		flakediag.Begin(t)
		scenario(t)
	})
}

// TestTransferAcceptance runs every Linux acceptance scenario against the
// real stack on both Linux and macOS. Each subtest owns a fresh fixture; the
// names are stable because CI requires every PASS line.
func TestTransferAcceptance(t *testing.T) {
	runTransferScenario(t, "roundtrip-file-both-directions", scenarioRoundTripFile)
	runTransferScenario(t, "roundtrip-directory-both-directions", scenarioRoundTripDirectory)
	runTransferScenario(t, "roundtrip-zero-byte-and-empty-directory", scenarioRoundTripEmpty)
	runTransferScenario(t, "roundtrip-names-with-spaces-and-non-ascii", scenarioRoundTripNames)
	runTransferScenario(t, "secrets-never-reach-results", scenarioSecrets)
	runTransferScenario(t, "overwrite-replaces-file-and-directory", scenarioOverwrite)
	runTransferScenario(t, "overwrite-failure-leaves-old-destination", scenarioOverwriteFailure)
	runTransferScenario(t, "refuse-path-traversal", scenarioRefuseTraversal)
	runTransferScenario(t, "refuse-absolute-and-drive-paths", scenarioRefuseAbsoluteAndDrive)
	runTransferScenario(t, "refuse-symlink-in-source-tree", scenarioRefuseSymlinkSource)
	runTransferScenario(t, "refuse-symlink-destination", scenarioRefuseSymlinkDestination)
	runTransferScenario(t, "refuse-download-forbidden-control-directory", scenarioRefuseForbiddenDestination)
	runTransferScenario(t, "refuse-destination-exists", scenarioRefuseDestinationExists)
	runTransferScenario(t, "refuse-overwrite-without-confirm", scenarioRefuseOverwriteWithoutConfirm)
	runTransferScenario(t, "refuse-unknown-root", scenarioRefuseUnknownRoot)
	runTransferScenario(t, "refuse-no-registered-roots", scenarioRefuseNoRoots)
	runTransferScenario(t, "refuse-over-limit-size-and-entries", scenarioRefuseOverLimit)
	runTransferScenario(t, "refuse-unapproved-target", scenarioRefuseUnapprovedTarget)
	runTransferScenario(t, "failure-connection-killed-mid-stream", scenarioFailureKilledMidStream)
	runTransferScenario(t, "failure-hash-mismatch-corruption", scenarioFailureCorruption)
	runTransferScenario(t, "failure-cancel-mid-transfer", scenarioFailureCancel)
	runTransferScenario(t, "failure-unsupported-remote", scenarioFailureUnsupportedRemote)
	runTransferScenario(t, "failure-unsupported-publication-primitive", scenarioFailureUnsupportedPublicationPrimitive)
	runTransferScenario(t, "manager-concurrency-and-duplicate-destination", scenarioManagerBounds)
	runTransferScenario(t, "chunk-remote-probe-capabilities", chunks.ScenarioChunkProbe)
	runTransferScenario(t, "chunk-remote-staging-lifecycle-and-foreign-objects", chunks.ScenarioChunkStagingLifecycle)
	runTransferScenario(t, "chunk-remote-part-upload-and-listing", chunks.ScenarioChunkPartsAndListing)
	runTransferScenario(t, "chunk-remote-assembly-and-publication", chunks.ScenarioChunkAssemblyAndPublication)
	runTransferScenario(t, "chunk-remote-garbage-collection", chunks.ScenarioChunkGarbageCollection)
	runTransferScenario(t, "chunk-remote-read-stat-and-disk", chunks.ScenarioChunkReadStatAndDisk)
	runTransferScenario(t, "chunk-upload-stream-drop-continues-chunked", chunks.ScenarioChunkUploadStreamDrop)
	runTransferScenario(t, "chunk-upload-drop-mid-chunk", chunks.ScenarioChunkUploadDropMidChunk)
	runTransferScenario(t, "chunk-upload-drop-during-assembly", chunks.ScenarioChunkUploadDropDuringAssembly)
	runTransferScenario(t, "chunk-upload-resume-by-new-engine", chunks.ScenarioChunkUploadResumeByNewEngine)
	runTransferScenario(t, "chunk-upload-source-changed", chunks.ScenarioChunkUploadSourceChanged)
	runTransferScenario(t, "chunk-upload-stale-staging-collected", chunks.ScenarioChunkUploadStaleStagingCollected)
	runTransferScenario(t, "chunk-upload-stall-detected-and-resumed", chunks.ScenarioChunkUploadStallDetectedAndResumed)
	runTransferScenario(t, "chunk-upload-leftover-assembly-cleaned", chunks.ScenarioChunkUploadLeftoverAssemblyCleaned)
	runTransferScenario(t, "chunk-download-stream-drop-continues-chunked", chunks.ScenarioChunkDownloadStreamDrop)
	runTransferScenario(t, "chunk-download-drop-mid-chunk", chunks.ScenarioChunkDownloadDropMidChunk)
	runTransferScenario(t, "chunk-download-drop-during-assembly", chunks.ScenarioChunkDownloadDropDuringAssembly)
	runTransferScenario(t, "chunk-download-resume-by-new-engine", chunks.ScenarioChunkDownloadResumeByNewEngine)
	runTransferScenario(t, "chunk-download-source-changed", chunks.ScenarioChunkDownloadSourceChanged)
	runTransferScenario(t, "chunk-download-stale-staging-collected", chunks.ScenarioChunkDownloadStaleStagingCollected)
	runTransferScenario(t, "chunk-download-stall-detected-and-resumed", chunks.ScenarioChunkDownloadStallDetectedAndResumed)
}
