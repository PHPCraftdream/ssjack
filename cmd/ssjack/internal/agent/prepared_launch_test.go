package agent

// Test-only seam for the remote MCP prepared-launch child. The production
// API is not widened: every seam helper that still lives outside this
// package (requireOutputFilterTerminal, selectOutputGuard, the output-filter
// warning text, the prepared owner endpoint/dial helpers, and the
// deterministic SSH key fixture) is injected through PreparedLaunchHelpers,
// and the positive marker is written from the injected Marker string so no
// runtime export is created. Assertions are the unchanged prepared-launch
// body; the full remote suite moves into this package as agent_test and
// calls AssertRemoteMCPPreparedLaunch through this seam.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/credential"
	startupkey "github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// PreparedLaunchHelpers carries the out-of-package seam helpers the
// prepared-launch child needs. They are injected as values/functions so the
// production output filter behavior stays exactly the CLI implementation.
type PreparedLaunchHelpers struct {
	// OwnerEndpoint captures the prepared owner endpoint before cleanup.
	OwnerEndpoint func(t *testing.T, path string) ownerlocal.Endpoint
	// OwnerDial proves the live owner IPC endpoint accepts a local peer.
	OwnerDial func(t *testing.T, ctx context.Context, path string, serviceDone <-chan struct{})
	// OwnerDialRefused proves the endpoint is absent after cleanup.
	OwnerDialRefused func(t *testing.T, ctx context.Context, path string, endpoint ownerlocal.Endpoint)
	// SSHKeyPEM renders the deterministic synthetic SSH key literal.
	SSHKeyPEM func(private ed25519.PrivateKey, comment string) []byte
	// RequireOutputFilterTerminal retains trusted-terminal admission.
	RequireOutputFilterTerminal func() error
	// SelectOutputGuard is the production guard selection seam.
	SelectOutputGuard func(provider remote.GuardProvider, disabled bool, warning io.Writer) (remote.GuardProvider, error)
	// OutputFilterWarning is the production bypass warning text.
	OutputFilterWarning string
	// Marker is the positive completion marker written to stdout at the end.
	Marker string
}

// AssertRemoteMCPPreparedLaunch is the test-only prepared-launch child: it
// exercises the real authenticated remote MCP launch, its guards, the owner
// receipt and the ordered cleanup, then writes the positive marker.
func AssertRemoteMCPPreparedLaunch(t *testing.T, ctx context.Context, path string, profile string, helpers PreparedLaunchHelpers) {
	t.Helper()
	if err := helpers.RequireOutputFilterTerminal(); err != nil {
		t.Fatal("prepared launch did not retain trusted-terminal admission")
	}
	secret := []byte("synthetic remote MCP startup database password")
	defer clear(secret)
	startup := startupsecret.New(string(secret), true)
	defer startup.Close()
	ctx = startupkey.WithInput(ctx, startup)
	credentials, err := Load(ctx, path, profile)
	if err != nil || credentials == nil || credentials.capture == nil || credentials.mcpBridge == nil || credentials.mcpLaunch == nil || credentials.owner == nil || credentials.service == nil {
		if credentials != nil {
			code := 0
			var cleanupErr error
			credentials.Finish(&code, &cleanupErr)
			if code != 0 || cleanupErr != nil {
				t.Fatal("failed prepared launch could not clean partial credentials")
			}
		}
		t.Fatal("production direct loader did not retain its real authenticated MCP launch")
	}
	if len(credentials.targets) != 1 || credentials.targets[0] != profile {
		t.Fatal("startup selected a different SSH identity than the fixture")
	}
	if credentials.mcpBridge == nil {
		t.Fatal("production direct loader did not activate its supervised remote MCP bridge")
	}
	launch := credentials.mcpLaunch
	cleaned := false
	cleanup := func() bool {
		if cleaned {
			return true
		}
		cleaned = true
		code := 0
		var outcome error
		credentials.Finish(&code, &outcome)
		ok := code == 0 && outcome == nil
		if !ok {
			t.Error("prepared launch cleanup did not complete successfully")
		}
		select {
		case <-credentials.service.Done():
		default:
			t.Error("prepared launch owner service did not join")
			ok = false
		}
		if credentials.capture != nil || credentials.mcpLaunch != nil || credentials.mcpBridge != nil || credentials.channels != nil {
			t.Error("prepared launch credential handles remained after cleanup")
			ok = false
		}
		if _, guardErr := launch.Guard(); guardErr == nil {
			t.Error("retained launch guard survived cleanup")
			ok = false
		}
		if len(launch.Upstreams()) != 0 {
			t.Error("retained launch upstream survived cleanup")
			ok = false
		}
		if accessErr := credentials.withMCPLaunch(func(*mcpgrant.Launch) error { return nil }); accessErr == nil || accessErr.Error() != "remote MCP launch is unavailable" {
			t.Error("one-shot launch access remained available after cleanup")
			ok = false
		}
		return ok
	}
	defer cleanup()
	ownerEndpoint := helpers.OwnerEndpoint(t, path)

	helpers.OwnerDial(t, ctx, path, credentials.service.Done())
	ownerGuard, err := credentials.guard(ctx)
	if err != nil || ownerGuard == nil {
		t.Fatal("production owner guard was unavailable after adoption")
	}
	basicRaw := []byte("synthetic startup Basic credential")
	basicPair := []byte("synthetic-mcp-owner:synthetic startup Basic credential")
	basicEncoded := []byte(base64.StdEncoding.EncodeToString(basicPair))
	basicFull := append([]byte("Basic "), basicEncoded...)
	sshPrivate := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(sshPrivate)
	sshLiteral := helpers.SSHKeyPEM(sshPrivate, "synthetic startup SSH key")
	defer clear(sshLiteral)
	for _, literal := range [][]byte{basicRaw, basicFull, basicEncoded, []byte("synthetic MCP custom header"), sshLiteral} {
		assertGuardMasks(t, ownerGuard, literal)
	}

	launchGuard, err := launch.Guard()
	if err != nil || launchGuard == nil {
		t.Fatal("real launch did not retain its own output guard")
	}
	for _, literal := range [][]byte{basicRaw, basicFull, basicEncoded, []byte("synthetic MCP custom header")} {
		assertGuardMasks(t, launchGuard, literal)
	}

	metadata, status, receiptDigest, err := credentials.owner.(interface {
		MetadataSnapshot() (vault.DirectoryMetadata, vault.SessionStatus, [32]byte, error)
	}).MetadataSnapshot()
	if err != nil || status.Err != nil || status.Pending || status.Revision != 1 || status.SavedRevision != 1 || receiptDigest == ([32]byte{}) {
		t.Fatal("adopted owner did not retain the exact saved preference receipt")
	}
	diskDigest, err := credential.CredentialCipherDigest(path)
	if err != nil || diskDigest != receiptDigest {
		t.Fatal("owner receipt digest did not match the encrypted database on disk")
	}
	if len(metadata.RemoteMCP.Last) != 1 {
		t.Fatal("owner receipt recorded preferences beyond the confirmed profile")
	}
	bindings := metadata.RemoteMCP.Last[profile]
	if len(bindings) != 1 {
		t.Fatal("owner receipt omitted the confirmed nonempty binding")
	}
	binding := bindings[0]
	if binding.ServerRevision == 0 || binding.AccountRevision == 0 || binding.ServerID == "" || binding.AccountID == "" {
		t.Fatal("owner receipt binding was incomplete")
	}
	if configured := os.Getenv("SSJACK_REMOTE_MCP_EXPECTED_BINDING"); configured != fmt.Sprintf("%s/%s/%d/%d", binding.ServerID, binding.AccountID, binding.ServerRevision, binding.AccountRevision) {
		t.Fatal("owner receipt did not match the parent's exact fixture binding")
	}

	handles := launch.Upstreams()
	if len(handles) != 1 || handles[0] == nil {
		t.Fatal("real launch lost its minted upstream handle while the bridge owns it")
	}
	if accessErr := credentials.withMCPLaunch(func(*mcpgrant.Launch) error { return nil }); accessErr == nil || accessErr.Error() != "remote MCP launch is unavailable" {
		t.Fatal("bridge ownership did not consume one-shot launch access")
	}
	clear(basicPair)
	clear(basicFull)

	var defaultWarning bytes.Buffer
	defaultGuard, err := helpers.SelectOutputGuard(credentials.guard, false, &defaultWarning)
	if err != nil || defaultWarning.Len() != 0 || defaultGuard == nil {
		t.Fatal("default output enforcement changed or emitted a bypass warning")
	}
	defaultSnapshot, err := defaultGuard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertGuardMasks(t, defaultSnapshot, basicRaw)
	var bypassWarning bytes.Buffer
	bypassGuard, err := helpers.SelectOutputGuard(credentials.guard, true, &bypassWarning)
	if err != nil || bypassGuard == nil || bypassWarning.String() != helpers.OutputFilterWarning {
		t.Fatal("trusted-terminal explicit bypass omitted its production warning")
	}
	bypassSnapshot, err := bypassGuard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var passthrough bytes.Buffer
	writer, err := outputguard.NewWriter(bypassSnapshot, &passthrough)
	if err != nil {
		t.Fatal(err)
	}
	if n, writeErr := writer.Write(basicRaw); n != len(basicRaw) || writeErr != nil || writer.Close() != nil || !bytes.Equal(passthrough.Bytes(), basicRaw) {
		t.Fatal("explicit bypass did not disable only the selected model-output guard")
	}
	stillGuarded, err := launch.Guard()
	if err != nil || stillGuarded == nil {
		t.Fatal("--no-output-filter bypass removed the independent prepared-launch guard")
	}
	assertGuardMasks(t, stillGuarded, basicRaw)
	if !cleanup() {
		t.Fatal("prepared launch did not fully clean before positive marker")
	}
	helpers.OwnerDialRefused(t, ctx, path, ownerEndpoint)
	fmt.Fprintln(os.Stdout, helpers.Marker)
}
