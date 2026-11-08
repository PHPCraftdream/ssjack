package main

import (
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
)

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
