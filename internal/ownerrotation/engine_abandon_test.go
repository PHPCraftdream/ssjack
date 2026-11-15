package ownerrotation

import (
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestAbandonClosesAttemptedRotationLocally(t *testing.T) {
	engine, keeper, remote := testEngine(t, errors.New("connection lost"))
	if err := engine.Install(context.Background(), 8, 4, true); !errors.Is(err, ErrUncertain) {
		t.Fatalf("setup: uncertain add lost: %v", err)
	}
	if keeper.info.Phase != vault.RotationUnknown {
		t.Fatalf("setup phase = %s", keeper.info.Phase)
	}
	before := len(remote.calls)
	if err := engine.Abandon(context.Background(), keeper.revision, 4); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	if keeper.info.Phase != vault.RotationCancelled {
		t.Fatalf("phase = %s, want %s", keeper.info.Phase, vault.RotationCancelled)
	}
	for _, call := range remote.calls[before:] {
		if call == "add" || call == "verify" {
			t.Fatalf("abandon made remote call %q", call)
		}
	}
	if keeper.saved != keeper.revision {
		t.Fatalf("abandon not durable: revision %d saved %d", keeper.revision, keeper.saved)
	}
	if err := engine.Install(context.Background(), keeper.revision, 4, true); err == nil {
		t.Fatal("abandoned rotation admitted another install")
	}
	if err := engine.Verify(context.Background(), keeper.revision, 4); err == nil {
		t.Fatal("abandoned rotation admitted verification")
	}
}

func TestAbandonRefusesPhasesWithoutAnAttemptedAdd(t *testing.T) {
	t.Run("prepared", func(t *testing.T) {
		engine, keeper, _ := testEngine(t, nil)
		if err := engine.Abandon(context.Background(), keeper.revision, 4); err == nil {
			t.Fatal("prepared rotation was abandoned; it must use cancel")
		}
		if keeper.info.Phase != vault.RotationPrepared {
			t.Fatalf("phase = %s", keeper.info.Phase)
		}
	})
	t.Run("verified", func(t *testing.T) {
		engine, keeper, _ := testEngine(t, nil)
		if err := engine.Install(context.Background(), 8, 4, true); err != nil {
			t.Fatal(err)
		}
		if err := engine.Verify(context.Background(), keeper.revision, 4); err != nil {
			t.Fatal(err)
		}
		if err := engine.Abandon(context.Background(), keeper.revision, 4); err == nil {
			t.Fatal("verified rotation was abandoned; it must commit")
		}
		if keeper.info.Phase != vault.RotationVerified {
			t.Fatalf("phase = %s", keeper.info.Phase)
		}
	})
	t.Run("stale revision", func(t *testing.T) {
		engine, keeper, _ := testEngine(t, errors.New("connection lost"))
		_ = engine.Install(context.Background(), 8, 4, true)
		if err := engine.Abandon(context.Background(), keeper.revision-1, 4); err == nil {
			t.Fatal("abandon accepted a stale revision")
		}
		if keeper.info.Phase != vault.RotationUnknown {
			t.Fatalf("phase = %s", keeper.info.Phase)
		}
	})
}
