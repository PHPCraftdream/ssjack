package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func makeRemoteMCPChannelCredentials(t *testing.T, known remote.GuardProvider) *agentCredentials {
	t.Helper()
	ctx := context.Background()
	directory := mcpdirectory.New()
	serverID, err := directory.AddServer("fixture", "https://example.com/mcp")
	if err != nil {
		t.Fatal("could not create inert server fixture")
	}
	account := mcpdirectory.Account{ServerID: serverID, Name: "fixture-account", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-upstream-auth-literal")}}
	accountID, err := directory.AddAccount(account)
	if err != nil {
		t.Fatal("could not create inert account fixture")
	}
	server, stored := directory.Servers[serverID], directory.Accounts[accountID]
	capture, err := mcpgrant.NewCapture(ctx, "fixture-profile", 1, [32]byte{1}, []mcpgrant.Record{{ServerID: serverID, AccountID: accountID, Server: server, Account: stored}})
	if err != nil {
		t.Fatal("could not capture inert launch fixture")
	}
	binding := mcpdirectory.Binding{ServerID: serverID, AccountID: accountID, ServerRevision: server.Revision, AccountRevision: stored.Revision}
	launch, err := capture.Issue(ctx, "fixture-profile", 1, []mcpdirectory.Binding{binding})
	if err != nil {
		t.Fatal("could not mint inert launch fixture")
	}
	guard, err := outputguard.New(nil)
	if err != nil {
		t.Fatal("could not create empty bridge guard")
	}
	runtime, err := mcpbridge.Open(ctx, []mcpbridge.UpstreamHandle{&mcpbridge.LaunchUpstream{Upstream: launch.Upstreams()[0]}}, guard, func(closeCtx context.Context) error { return launch.Close(closeCtx) }, []mcpdirectory.Binding{binding})
	if err != nil {
		t.Fatal("could not open bridge fixture")
	}
	credentials := &agentCredentials{mcpBridge: runtime, mcpLaunch: launch, mcpLaunchUsed: true, guard: known, capture: capture}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if credentials.channels != nil {
			if err := credentials.channels.Close(cleanupCtx); err != nil {
				t.Errorf("channel cleanup did not join: %v", err)
			}
			credentials.channels = nil
		}
		if err := runtime.Close(cleanupCtx); err != nil {
			t.Errorf("bridge cleanup did not join: %v", err)
		}
		if err := capture.Close(cleanupCtx); err != nil {
			t.Errorf("capture cleanup did not complete: %v", err)
		}
	})
	return credentials
}

func applyRemoteMCPGuard(t *testing.T, guard *outputguard.Snapshot, input string) string {
	t.Helper()
	var output bytes.Buffer
	writer, err := outputguard.NewWriter(guard, &output)
	if err != nil {
		t.Fatal("guard writer creation failed")
	}
	if _, err := writer.Write([]byte(input)); err != nil {
		t.Fatal("guard writer rejected fixture")
	}
	if err := writer.Close(); err != nil {
		t.Fatal("guard writer did not close")
	}
	return output.String()
}

func TestPrepareRemoteMCPChannelsUnionsMandatoryGuardWithKnownOutput(t *testing.T) {
	known, err := outputguard.New([][]byte{[]byte("synthetic-ssh-key-literal"), []byte("synthetic-upstream-auth-literal")})
	if err != nil {
		t.Fatal("could not create known output guard")
	}
	credentials := makeRemoteMCPChannelCredentials(t, fixedOutputGuard(known))
	combined, _, err := prepareRemoteMCPChannels(context.Background(), credentials, credentials.guard, time.Minute)
	if err != nil {
		t.Fatal("channel setup refused a valid minted capability")
	}
	snapshot, err := combined(context.Background())
	if err != nil {
		t.Fatal("combined output guard was unavailable")
	}
	masked := applyRemoteMCPGuard(t, snapshot, "synthetic-ssh-key-literal synthetic-upstream-auth-literal "+credentials.channels.Descriptors()[0].Token)
	if strings.Contains(masked, "synthetic-ssh-key-literal") || strings.Contains(masked, "synthetic-upstream-auth-literal") || strings.Contains(masked, credentials.channels.Descriptors()[0].Token) || strings.Count(masked, outputguard.Marker) != 3 {
		t.Fatal("channel preparation dropped a pre-existing output literal")
	}
}

func TestPrepareRemoteMCPChannelsKeepsMandatoryGuardWhenKnownOutputEmpty(t *testing.T) {
	empty, err := outputguard.New(nil)
	if err != nil {
		t.Fatal("could not create empty known guard")
	}
	credentials := makeRemoteMCPChannelCredentials(t, fixedOutputGuard(empty))
	combined, _, err := prepareRemoteMCPChannels(context.Background(), credentials, credentials.guard, time.Minute)
	if err != nil {
		t.Fatal("channel setup refused an empty known output guard")
	}
	snapshot, err := combined(context.Background())
	if err != nil {
		t.Fatal("combined output guard was unavailable")
	}
	descriptors := credentials.channels.Descriptors()
	if len(descriptors) != 1 || descriptors[0].Token == "" {
		t.Fatal("channel capability fixture was not created")
	}
	// No-output-filter selection suppresses known output literals, not the
	// private loopback channel token guard.
	masked := applyRemoteMCPGuard(t, snapshot, "synthetic-ssh-key-literal "+descriptors[0].Token+" ordinary-visible-text")
	if masked != "synthetic-ssh-key-literal "+outputguard.Marker+" ordinary-visible-text" {
		t.Fatal("empty known-output filtering bypassed mandatory local channel redaction or changed ordinary output")
	}
}
