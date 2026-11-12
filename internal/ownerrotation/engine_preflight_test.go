package ownerrotation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestInstallPreflightFailureLeavesPreparedAndNeverAttempts(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	remote.preflightErr = errors.New("no usable client config")
	err := engine.Install(context.Background(), 8, 4, true)
	if !errors.Is(err, remote.preflightErr) {
		t.Fatalf("preflight error lost: %v", err)
	}
	if keeper.info.Phase != vault.RotationPrepared || keeper.revision != 8 {
		t.Fatalf("phase=%s revision=%d", keeper.info.Phase, keeper.revision)
	}
	if contains(remote.calls, "add") || remote.persistCalls != 1 || remote.preflights != 1 {
		t.Fatalf("calls=%v persists=%d preflights=%d", remote.calls, remote.persistCalls, remote.preflights)
	}
	if err := engine.Cancel(context.Background(), 8, 4); err != nil {
		t.Fatalf("prepared plan not cancellable after preflight failure: %v", err)
	}
}

func TestInstallInsufficientRemainingTimeLeavesPrepared(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), minAddWindow-5*time.Second)
	defer cancel()
	if err := engine.Install(ctx, 8, 4, true); err == nil {
		t.Fatal("install accepted without time for the remote addition")
	}
	if keeper.info.Phase != vault.RotationPrepared || keeper.revision != 8 {
		t.Fatalf("phase=%s revision=%d", keeper.info.Phase, keeper.revision)
	}
	if contains(remote.calls, "add") || remote.preflights != 0 || remote.persistCalls != 1 {
		t.Fatalf("calls=%v persists=%d preflights=%d", remote.calls, remote.persistCalls, remote.preflights)
	}
}

func TestInstallWithAmpleTimeRunsPreflightOnceBeforeAdd(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	if err := engine.Install(context.Background(), 8, 4, true); err != nil {
		t.Fatal(err)
	}
	if remote.preflights != 1 || keeper.info.Phase != vault.RotationAdded {
		t.Fatalf("preflights=%d phase=%s", remote.preflights, keeper.info.Phase)
	}
}
