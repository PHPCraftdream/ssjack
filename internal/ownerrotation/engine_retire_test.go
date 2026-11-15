package ownerrotation

import (
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func completedEngine(t *testing.T) (*Engine, *memoryKeeper, *memoryRemote) {
	t.Helper()
	engine, keeper, remote := testEngine(t, nil)
	if err := engine.Install(context.Background(), 8, 4, true); err != nil {
		t.Fatal(err)
	}
	if err := engine.Verify(context.Background(), keeper.revision, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Commit(context.Background(), keeper.revision, 4); err != nil {
		t.Fatal(err)
	}
	if keeper.info.Phase != vault.RotationComplete {
		t.Fatalf("setup phase = %s", keeper.info.Phase)
	}
	return engine, keeper, remote
}

func TestRetireRemovesOnlyTheOldKeyAfterCompletionAndChangesNoState(t *testing.T) {
	engine, keeper, remote := completedEngine(t)
	revision, phase := keeper.revision, keeper.info.Phase
	for attempt := 0; attempt < 2; attempt++ {
		if err := engine.Retire(context.Background(), revision, 4); err != nil {
			t.Fatalf("retire attempt %d: %v", attempt, err)
		}
	}
	want := [2]string{"old", "new"}
	if len(remote.retired) != 2 || remote.retired[0] != want || remote.retired[1] != want {
		t.Fatalf("retired keys = %v, want the journal's old and new public keys twice", remote.retired)
	}
	if keeper.revision != revision || keeper.info.Phase != phase {
		t.Fatalf("retire changed the journal: revision %d phase %s", keeper.revision, keeper.info.Phase)
	}
}

func TestRetireRefusesBeforeCompletionWithoutRemoteCalls(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	if err := engine.Retire(context.Background(), keeper.revision, 4); err == nil {
		t.Fatal("prepared rotation retired the old key")
	}
	if err := engine.Install(context.Background(), 8, 4, true); err != nil {
		t.Fatal(err)
	}
	if err := engine.Retire(context.Background(), keeper.revision, 4); err == nil {
		t.Fatal("added rotation retired the old key; the new key is not yet committed")
	}
	if err := engine.Verify(context.Background(), keeper.revision, 4); err != nil {
		t.Fatal(err)
	}
	if err := engine.Retire(context.Background(), keeper.revision, 4); err == nil {
		t.Fatal("verified rotation retired the old key; it must commit first")
	}
	if len(remote.retired) != 0 || contains(remote.calls, "retire") {
		t.Fatalf("refused retirement reached the remote: %v", remote.calls)
	}
}

func TestRetirePropagatesRemoteFailureAndStaleRevision(t *testing.T) {
	engine, keeper, remote := completedEngine(t)
	remote.retireErr = errors.New("connection lost")
	if err := engine.Retire(context.Background(), keeper.revision, 4); !errors.Is(err, remote.retireErr) {
		t.Fatalf("remote failure = %v", err)
	}
	remote.retireErr = nil
	before := len(remote.retired)
	if err := engine.Retire(context.Background(), keeper.revision-1, 4); err == nil {
		t.Fatal("retire accepted a stale revision")
	}
	if len(remote.retired) != before {
		t.Fatal("stale retirement reached the remote")
	}
}
