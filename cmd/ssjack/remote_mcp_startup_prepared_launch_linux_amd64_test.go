//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func remoteMCPPreparedLaunchChild(t *testing.T, ctx context.Context, path string, profile string) {
	t.Helper()
	if err := requireOutputFilterTerminal(); err != nil {
		t.Fatal("prepared launch did not retain trusted-terminal admission")
	}
	secret := []byte("synthetic remote MCP startup database password")
	defer clear(secret)
	startup := startupsecret.New(string(secret), true)
	defer startup.Close()
	ctx = context.WithValue(ctx, startupPasswordKey{}, startup)
	credentials, err := loadAgentCredentials(ctx, path, profile)
	if err != nil || credentials == nil || credentials.capture == nil || credentials.mcpLaunch == nil || credentials.owner == nil || credentials.service == nil {
		if credentials != nil {
			code := 0
			var cleanupErr error
			finishAgentCredentials(credentials, &code, &cleanupErr)
			if code != 0 || cleanupErr != nil {
				t.Fatal("failed prepared launch could not clean partial credentials")
			}
		}
		t.Fatal("production direct loader did not retain its real authenticated MCP launch")
	}
	if len(credentials.targets) != 1 || credentials.targets[0] != profile {
		t.Fatal("startup selected a different SSH identity than the fixture")
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
		finishAgentCredentials(credentials, &code, &outcome)
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
		if credentials.capture != nil || credentials.mcpLaunch != nil {
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
		if accessErr := credentials.WithMCPLaunch(func(*mcpgrant.Launch) error { return nil }); accessErr == nil || accessErr.Error() != "remote MCP launch is unavailable" {
			t.Error("one-shot launch access remained available after cleanup")
			ok = false
		}
		return ok
	}
	defer cleanup()

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
	sshLiteral := remoteMCPDeterministicSSHKeyPEM(sshPrivate, "synthetic startup SSH key")
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
	diskDigest, err := credentialCipherDigest(path)
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

	// Take is lazy. The transport is not connected or used for a request.
	upstreamCount := 0
	if err := credentials.WithMCPLaunch(func(got *mcpgrant.Launch) error {
		if got != launch {
			return errors.New("unexpected launch object")
		}
		handles := got.Upstreams()
		if len(handles) != 1 || handles[0] == nil {
			return errors.New("real launch omitted its one selected upstream")
		}
		upstreamCount = len(handles)
		transport, takeErr := handles[0].Take()
		if takeErr != nil || transport == nil {
			return errors.New("real upstream refused its first lazy one-shot take")
		}
		if again, secondErr := handles[0].Take(); again != nil || secondErr == nil {
			return errors.New("real upstream accepted a second take")
		}
		if guard, guardErr := got.Guard(); guardErr != nil || guard == nil {
			return errors.New("real launch guard did not survive adoption and first use")
		}
		return nil
	}); err != nil || upstreamCount == 0 {
		t.Fatal("one-shot production launch use failed")
	}
	clear(basicPair)
	clear(basicFull)

	var defaultWarning bytes.Buffer
	defaultGuard, err := selectOutputGuard(credentials.guard, false, &defaultWarning)
	if err != nil || defaultWarning.Len() != 0 || defaultGuard == nil {
		t.Fatal("default output enforcement changed or emitted a bypass warning")
	}
	defaultSnapshot, err := defaultGuard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertGuardMasks(t, defaultSnapshot, basicRaw)
	var bypassWarning bytes.Buffer
	bypassGuard, err := selectOutputGuard(credentials.guard, true, &bypassWarning)
	if err != nil || bypassGuard == nil || bypassWarning.String() != outputFilterWarning {
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
	fmt.Fprintln(os.Stdout, remoteMCPPreparedMarker)
}
