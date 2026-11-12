package ownerrotation

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestInstallPersistsAttemptBeforeEffectAndVerifyNeverReplays(t *testing.T) {
	engine, keeper, remote := testEngine(t, errors.New("connection lost"))
	if err := engine.Install(context.Background(), 8, 4, true); !errors.Is(err, ErrUncertain) {
		t.Fatalf("uncertain result lost: %v", err)
	}
	if keeper.info.Phase != vault.RotationUnknown {
		t.Fatalf("phase=%s", keeper.info.Phase)
	}
	want := []string{"persist", "persist", "add", "persist"}
	if !reflect.DeepEqual(remote.calls, want) {
		t.Fatalf("calls=%v want=%v", remote.calls, want)
	}
	recovered, err := New(keeper, remote, engine.persist)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]string(nil), remote.calls...)
	if err := recovered.Install(context.Background(), keeper.revision, 4, true); err == nil {
		t.Fatal("unknown outcome replayed")
	}
	if !reflect.DeepEqual(remote.calls, before) {
		t.Fatalf("unknown Install made calls: %v", remote.calls)
	}
	if err := recovered.Verify(context.Background(), keeper.revision, 4); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Install(context.Background(), keeper.revision, 4, true); err == nil {
		t.Fatal("verified rotation admitted a second install")
	}
	want = []string{"persist", "persist", "add", "persist", "persist", "verify", "persist"}
	if !reflect.DeepEqual(remote.calls, want) {
		t.Fatalf("recovery order=%v", remote.calls)
	}
}

func TestInstallPersistenceFailuresPreventAdd(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(map[int]string{1: "precondition", 2: "attempting"}[failAt], func(t *testing.T) {
			engine, keeper, remote := testEngine(t, nil)
			remote.failPersist = failAt
			if err := engine.Install(context.Background(), 8, 4, true); err == nil {
				t.Fatal("persistence failure accepted")
			}
			wantPhase := vault.RotationPrepared
			wantCalls := []string{"persist"}
			if failAt == 2 {
				wantPhase = vault.RotationAttempting
				wantCalls = append(wantCalls, "persist")
			}
			if keeper.info.Phase != wantPhase {
				t.Fatalf("phase=%s want=%s", keeper.info.Phase, wantPhase)
			}
			if !reflect.DeepEqual(remote.calls, wantCalls) {
				t.Fatalf("calls=%v want=%v", remote.calls, wantCalls)
			}
		})
	}
}

func TestVerifiedDurablyPrecedesCommitAndCompletionProof(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	if err := engine.Install(context.Background(), 8, 4, true); err != nil {
		t.Fatal(err)
	}
	if err := engine.Verify(context.Background(), keeper.revision, 4); err != nil {
		t.Fatal(err)
	}
	if keeper.info.Phase != vault.RotationVerified || keeper.saved != keeper.revision {
		t.Fatalf("verification not durable: %+v", keeper)
	}
	plan, err := engine.Commit(context.Background(), keeper.revision, 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"persist", "persist", "add", "persist", "persist", "verify", "persist", "persist", "commit", "persist", "complete", "persist"}
	if !reflect.DeepEqual(remote.calls, want) {
		t.Fatalf("ordering=%v want=%v", remote.calls, want)
	}
	if plan.Info.Phase != vault.RotationComplete || plan.Info.CommitRevision == 0 || plan.Info.CommitDigest != hex.EncodeToString(keeper.completionProof[:]) || keeper.info.CommitDigest != plan.Info.CommitDigest || keeper.saved != keeper.revision {
		t.Fatalf("completion metadata not keeper-backed/durable: %+v", plan.Info)
	}
}

func TestCommitFailuresDoNotCompleteOrReportSuccess(t *testing.T) {
	t.Run("commit persistence", func(t *testing.T) {
		engine, keeper, remote := testEngine(t, nil)
		keeper.info.Phase = vault.RotationVerified
		remote.failPersist = 2
		if _, err := engine.Commit(context.Background(), 8, 4); err == nil {
			t.Fatal("unsaved commit reported success")
		}
		if keeper.info.Phase != vault.RotationCommitted || contains(remote.calls, "complete") {
			t.Fatalf("phase=%s calls=%v", keeper.info.Phase, remote.calls)
		}
	})
	t.Run("complete persistence", func(t *testing.T) {
		engine, keeper, remote := testEngine(t, nil)
		keeper.info.Phase = vault.RotationVerified
		remote.failPersist = 3
		if _, err := engine.Commit(context.Background(), 8, 4); err == nil {
			t.Fatal("unsaved completion reported success")
		}
		if keeper.info.Phase != vault.RotationComplete || keeper.saved == keeper.revision {
			t.Fatalf("completion durability unreported: phase=%s saved=%d revision=%d", keeper.info.Phase, keeper.saved, keeper.revision)
		}
	})
	t.Run("commit mutation", func(t *testing.T) {
		engine, keeper, remote := testEngine(t, nil)
		keeper.info.Phase = vault.RotationVerified
		keeper.failCommit = errors.New("commit rejected")
		if _, err := engine.Commit(context.Background(), 8, 4); err == nil {
			t.Fatal("commit failure accepted")
		}
		if keeper.info.Phase != vault.RotationVerified || contains(remote.calls, "complete") {
			t.Fatalf("phase=%s calls=%v", keeper.info.Phase, remote.calls)
		}
	})
	t.Run("complete mutation", func(t *testing.T) {
		engine, keeper, _ := testEngine(t, nil)
		keeper.info.Phase = vault.RotationVerified
		keeper.failComplete = errors.New("complete rejected")
		if _, err := engine.Commit(context.Background(), 8, 4); err == nil {
			t.Fatal("completion failure accepted")
		}
		if keeper.info.Phase != vault.RotationCommitted || keeper.info.CommitDigest != "" {
			t.Fatalf("failed completion fabricated success: %+v", keeper.info)
		}
	})
}

func TestVerifyFailureLeavesPriorPhaseAndNeverCommits(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	if err := engine.Install(context.Background(), 8, 4, true); err != nil {
		t.Fatal(err)
	}
	remote.verifyErr = errors.New("new key rejected")
	if err := engine.Verify(context.Background(), keeper.revision, 4); err == nil {
		t.Fatal("verification failure accepted")
	}
	if keeper.info.Phase != vault.RotationAdded || contains(remote.calls, "commit") || contains(remote.calls, "complete") {
		t.Fatalf("phase=%s calls=%v", keeper.info.Phase, remote.calls)
	}
}

func TestCancelledContextPreventsEffects(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.Install(ctx, 8, 4, true); err == nil {
		t.Fatal("cancelled install accepted")
	}
	if err := engine.Verify(ctx, 8, 4); err == nil {
		t.Fatal("cancelled verify accepted")
	}
	if _, err := engine.Commit(ctx, 8, 4); err == nil {
		t.Fatal("cancelled commit accepted")
	}
	if err := engine.Cancel(ctx, 8, 4); err == nil {
		t.Fatal("cancelled cancel accepted")
	}
	if len(remote.calls) != 0 || keeper.info.Phase != vault.RotationPrepared || keeper.revision != 8 {
		t.Fatalf("cancelled operation had effects: calls=%v keeper=%+v", remote.calls, keeper)
	}
}

func TestCancellationDuringAttemptPersistencePreventsAdd(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	engine.persist = func(context.Context) (Evidence, error) {
		calls++
		keeper.saved = keeper.revision
		digest := [32]byte{byte(keeper.revision), 1}
		keeper.digest = digest
		if calls == 2 {
			cancel()
		}
		return Evidence{Revision: keeper.revision, Digest: digest}, nil
	}
	if err := engine.Install(ctx, 8, 4, true); err == nil {
		t.Fatal("cancelled persistence accepted")
	}
	if keeper.info.Phase != vault.RotationAttempting || contains(remote.calls, "add") {
		t.Fatalf("phase=%s calls=%v", keeper.info.Phase, remote.calls)
	}
}

func TestStaleUnconfirmedAndEffectfulCancelRejected(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	if err := engine.Install(context.Background(), 7, 4, true); !errors.Is(err, vault.ErrOwnerRevision) {
		t.Fatalf("stale revision: %v", err)
	}
	if err := engine.Install(context.Background(), 8, 4, false); err == nil {
		t.Fatal("unconfirmed install accepted")
	}
	if err := engine.Install(context.Background(), 8, 4, true); err != nil {
		t.Fatal(err)
	}
	if err := engine.Cancel(context.Background(), keeper.revision, 4); err == nil {
		t.Fatal("effectful cancel accepted")
	}
	if !reflect.DeepEqual(remote.calls[:3], []string{"persist", "persist", "add"}) {
		t.Fatalf("effect preceded durable attempt: %v", remote.calls)
	}
}

func TestAttemptingRecoveryIsVerifyOnly(t *testing.T) {
	engine, keeper, remote := testEngine(t, nil)
	if err := keeper.SetRotationPhaseAt(8, 4, vault.RotationAttempting); err != nil {
		t.Fatal(err)
	}
	keeper.saved = keeper.revision
	engine.persist = func(context.Context) (Evidence, error) {
		remote.calls = append(remote.calls, "persist")
		keeper.saved = keeper.revision
		digest := [32]byte{1}
		keeper.digest = digest
		return Evidence{Revision: keeper.revision, Digest: digest}, nil
	}
	if err := engine.Verify(context.Background(), keeper.revision, 4); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(remote.calls, []string{"persist", "verify", "persist"}) {
		t.Fatalf("attempting recovery replayed Add: %v", remote.calls)
	}
}
