package main

import (
	"context"
	"errors"
	"testing"
	"time"

	mcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

type stubUp struct{}

type emptyChannelHandler struct{}

func (emptyChannelHandler) Describe(context.Context) ([]byte, error) { return []byte(`{}`), nil }
func (emptyChannelHandler) Call(context.Context, string, []byte) ([]byte, error) {
	return []byte(`{}`), nil
}

func (stubUp) TakeTransport() (mcp.Transport, error) {
	return nil, errors.New("unused in finish tests")
}

// bridgeRuntimeFixture builds a real bridge runtime around a stub upstream so
// finish-order tests exercise the actual Close path.
func bridgeRuntimeFixture(t *testing.T, closeLaunch func(context.Context) error) *mcpbridge.Runtime {
	t.Helper()
	guard, err := outputguard.New(nil) // empty pattern set is valid
	if err != nil {
		t.Fatal(err)
	}
	rt, err := mcpbridge.Open(context.Background(), []mcpbridge.UpstreamHandle{stubUp{}}, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := rt.Close(ctx); err != nil {
			t.Errorf("bridge fixture cleanup did not join: %v", err)
		}
	})
	return rt
}

func TestWithMCPLaunchIsOneShotAndKeepsCleanupOwnership(t *testing.T) {
	launch := &mcpgrant.Launch{}
	credentials := &agentCredentials{mcpLaunch: launch}
	calls := 0
	if err := credentials.WithMCPLaunch(func(got *mcpgrant.Launch) error {
		calls++
		if got != launch {
			t.Fatal("callback received a different launch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || credentials.mcpLaunch != launch {
		t.Fatal("launch access consumed the owned cleanup handle")
	}
	if err := credentials.WithMCPLaunch(func(*mcpgrant.Launch) error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatal("launch callback was not one-shot")
	}
}

func TestWithMCPLaunchMarksAttemptConsumedWhenCallbackFails(t *testing.T) {
	launch := &mcpgrant.Launch{}
	credentials := &agentCredentials{mcpLaunch: launch}
	failure := errors.New("synthetic callback failure")
	if err := credentials.WithMCPLaunch(func(*mcpgrant.Launch) error { return failure }); !errors.Is(err, failure) {
		t.Fatal("callback error was not returned")
	}
	if credentials.mcpLaunch != launch {
		t.Fatal("callback failure dropped cleanup ownership")
	}
	if err := credentials.WithMCPLaunch(func(*mcpgrant.Launch) error { return nil }); err == nil {
		t.Fatal("failed callback left launch access reusable")
	}
}

func TestFinishAgentCredentialsRetainsFailedLaunchCleanup(t *testing.T) {
	launch := &mcpgrant.Launch{}
	ownerCloses := 0
	credentials := &agentCredentials{
		mcpLaunch: launch,
		owner: ownerCloseFunc(func(errorContext context.Context) error {
			ownerCloses++
			return nil
		}),
	}
	code := 0
	var result error
	finishAgentCredentials(credentials, &code, &result)
	if code != 1 || !errors.Is(result, errOwnerShutdown) {
		t.Fatal("failed launch cleanup was not reported")
	}
	if credentials.mcpLaunch != launch || ownerCloses != 0 {
		t.Fatal("failed launch cleanup was dropped or owner closed prematurely")
	}
}

func TestFinishAgentCredentialsClosesChannelsBeforeBridge(t *testing.T) {
	channels, err := mcpchannel.Open(context.Background(), 1, time.Minute, func(int) mcpchannel.Handler { return emptyChannelHandler{} })
	if err != nil {
		t.Fatal("could not open owned channel fixture")
	}
	bridgeClosed := false
	runtime := bridgeRuntimeFixture(t, func(context.Context) error {
		select {
		case <-channels.Done():
		default:
			t.Fatal("bridge close ran before owned channels joined")
		}
		bridgeClosed = true
		return nil
	})
	credentials := &agentCredentials{channels: channels, mcpBridge: runtime, mcpLaunch: &mcpgrant.Launch{}, mcpLaunchUsed: true}
	code := 0
	var result error
	finishAgentCredentials(credentials, &code, &result)
	if code != 0 || result != nil || !bridgeClosed || credentials.channels != nil || credentials.mcpBridge != nil {
		t.Fatal("credential cleanup did not join channels before the bridge")
	}
}

func TestFinishAgentCredentialsClosesBridgeBeforeOwner(t *testing.T) {
	sequence := 0
	closeRun, ownerRun := 0, 0
	var bridgeClosed bool
	credentials := &agentCredentials{
		mcpBridge: bridgeRuntimeFixture(t, func(context.Context) error {
			sequence++
			closeRun = sequence
			bridgeClosed = true
			return nil
		}),
		mcpLaunch:     &mcpgrant.Launch{},
		mcpLaunchUsed: true,
		owner: ownerCloseFunc(func(context.Context) error {
			if !bridgeClosed {
				t.Fatal("owner close ran before bridge session joined")
			}
			sequence++
			ownerRun = sequence
			return nil
		}),
	}
	code := 0
	var result error
	finishAgentCredentials(credentials, &code, &result)
	if code != 0 || result != nil {
		t.Fatal("successful bridge close was reported as a failure")
	}
	if closeRun != 1 || ownerRun != 2 {
		t.Fatal("bridge or owner close did not run exactly once")
	}
	if ownerRun <= closeRun {
		t.Fatal("owner closed before the bridge")
	}
	if credentials.mcpBridge != nil || credentials.mcpLaunch != nil {
		t.Fatal("bridge close did not clear the bridge and launch handles")
	}
}

func TestFinishAgentCredentialsRetainsFailedBridgeCleanup(t *testing.T) {
	closeCalls := 0
	closeLaunch := func(context.Context) error {
		closeCalls++
		if closeCalls == 1 {
			return errors.New("synthetic bridge close failure")
		}
		return nil
	}
	rt := bridgeRuntimeFixture(t, closeLaunch)
	credentials := &agentCredentials{
		mcpBridge:     rt,
		mcpLaunch:     &mcpgrant.Launch{},
		mcpLaunchUsed: true,
		owner: ownerCloseFunc(func(context.Context) error {
			t.Fatal("owner must not close after a failed bridge cleanup")
			return nil
		}),
	}
	code := 0
	var result error
	finishAgentCredentials(credentials, &code, &result)
	if code != 1 || !errors.Is(result, errOwnerShutdown) {
		t.Fatal("failed bridge cleanup was not reported")
	}
	if credentials.mcpBridge == nil {
		t.Fatal("failed bridge cleanup dropped the retained bridge state")
	}
}

func TestBridgeConsumesLaunchOneShotAccess(t *testing.T) {
	credentials := &agentCredentials{
		mcpBridge:     bridgeRuntimeFixture(t, func(context.Context) error { return nil }),
		mcpLaunch:     &mcpgrant.Launch{},
		mcpLaunchUsed: true,
	}
	if err := credentials.WithMCPLaunch(func(*mcpgrant.Launch) error { return nil }); err == nil || err.Error() != "remote MCP launch is unavailable" {
		t.Fatal("active bridge did not refuse direct launch access")
	}
}
