package main

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
)

func TestAppstoreScopedCLICanceledSecretDoesNotMutate(t *testing.T) {
	if os.Getenv("SSJACK_TEST_SCOPED_KDF") != "1" {
		t.Skip("private scoped acceptance only")
	}
	f := newAppstoreReplayFixture(t)
	before := f.accepted.Load()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var prompts atomic.Int64
	old := appstoreReadInput
	appstoreReadInput = func(_ string, _ bool) ([]byte, error) {
		switch prompts.Add(1) {
		case 1:
			return []byte(f.master), nil
		case 2:
			cancel()
			return []byte(f.secret), nil
		default:
			t.Fatal("unexpected additional input prompt")
			return nil, os.ErrClosed
		}
	}
	defer func() { appstoreReadInput = old }()
	out, stderr, code, err := captureAppstoreOutput(t, func() (int, error) {
		return run(ctx, []string{"appstore", "put", f.dir})
	})
	if code == 0 || err == nil {
		t.Fatalf("canceled secret collection accepted: %d %v", code, err)
	}
	if got := prompts.Load(); got != 2 {
		t.Fatalf("input prompts=%d, want 2", got)
	}
	noSecretOutput(t, out+stderr, f.master, f.secret)
	state := f.anchorState(t)
	if state.Sequence() != 0 || state.JournalCount() != 0 {
		t.Fatalf("canceled secret collection changed anchor: sequence=%d journal=%d", state.Sequence(), state.JournalCount())
	}
	if got := f.accepted.Load() - before; got != 1 {
		t.Fatalf("accepted requests=%d, want initial CLI read only (1)", got)
	}
}

func TestAppstoreScopedCLILostCommitAckNoBlindReplay(t *testing.T) {
	if os.Getenv("SSJACK_TEST_SCOPED_KDF") != "1" {
		t.Skip("private scoped acceptance only")
	}
	f := newAppstoreReplayFixture(t)
	before := f.accepted.Load()
	f.drop.Store(true)
	f.denyRead.Store(true)
	restore := f.input([]byte(f.master), []byte(f.secret))
	out, stderr, code, err := captureAppstoreOutput(t, func() (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return run(ctx, []string{"appstore", "put", f.dir})
	})
	restore()
	if code == 0 || err == nil {
		t.Fatalf("unreconciled lost acknowledgement succeeded: %d %v", code, err)
	}
	if !f.dropped.Load() {
		t.Fatal("service did not drop the committed response")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "inspect") && !strings.Contains(strings.ToLower(err.Error()), "reconcile") {
		t.Fatalf("error does not describe inspection/reconciliation: %v", err)
	}
	noSecretOutput(t, out+stderr, f.master, f.secret)
	if strings.TrimSpace(out) != "" || strings.Contains(out, "$ssjack") {
		t.Fatalf("uncertain mutation emitted stdout: %q", out)
	}
	state := f.anchorState(t)
	if state.Sequence() != 1 || state.JournalCount() != 1 {
		t.Fatalf("lost acknowledgement state: sequence=%d journal=%d", state.Sequence(), state.JournalCount())
	}
	if got := f.accepted.Load() - before; got != 7 {
		t.Fatalf("connections=%d, want CLI read, writer read, reservation reconciliation read, reserve plus confirmation read, commit plus reconciliation read (7)", got)
	}

	f.denyRead.Store(false)
	before = f.accepted.Load()
	oldSecond := appstoreReadInput
	var secondPrompts atomic.Int64
	appstoreReadInput = func(_ string, _ bool) ([]byte, error) {
		if secondPrompts.Add(1) == 1 {
			return []byte(f.master), nil
		}
		t.Fatal("unexpected additional input prompt")
		return nil, os.ErrClosed
	}
	defer func() { appstoreReadInput = oldSecond }()
	out, stderr, code, err = captureAppstoreOutput(t, func() (int, error) {
		return run(context.Background(), []string{"appstore", "put", f.dir})
	})
	if code == 0 || err == nil {
		t.Fatalf("second first-entry put unexpectedly succeeded: %d %v", code, err)
	}
	noSecretOutput(t, out+stderr, f.master, f.secret)
	if got := f.accepted.Load() - before; got != 1 {
		t.Fatalf("second invocation accepted requests=%d, want read-only preflight (1)", got)
	}
	state = f.anchorState(t)
	if state.Sequence() != 1 || state.JournalCount() != 1 {
		t.Fatalf("second invocation changed committed state: sequence=%d journal=%d", state.Sequence(), state.JournalCount())
	}
}

func TestAppstoreScopedCLILostCommitAckReconcilesWithoutReplay(t *testing.T) {
	if os.Getenv("SSJACK_TEST_SCOPED_KDF") != "1" {
		t.Skip("private scoped acceptance only")
	}
	f := newAppstoreReplayFixture(t)
	before := f.accepted.Load()
	f.drop.Store(true)
	f.denyRead.Store(false)
	var calls int
	old := appstoreReadInput
	appstoreReadInput = func(_ string, _ bool) ([]byte, error) {
		calls++
		switch calls {
		case 1:
			return []byte(f.master), nil
		case 2:
			return []byte(f.secret), nil
		default:
			t.Fatal("unexpected additional input prompt")
			return nil, os.ErrClosed
		}
	}
	defer func() { appstoreReadInput = old }()
	out, stderr, code, err := captureAppstoreOutput(t, func() (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return run(ctx, []string{"appstore", "put", f.dir})
	})
	if code != 0 || err != nil {
		t.Fatalf("reconciled lost acknowledgement failed: code=%d err=%v", code, err)
	}
	if !f.dropped.Load() {
		t.Fatal("service did not drop the committed response")
	}
	if calls != 2 {
		t.Fatalf("input prompts=%d, want exactly 2", calls)
	}
	noSecretOutput(t, out+stderr, f.master, f.secret)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || lines[1] != "sequence=1 revision=1" {
		t.Fatalf("unexpected safe CLI result: %q", out)
	}
	ref, err := appstoreplaceholder.Parse([]byte(lines[0]))
	if err != nil {
		t.Fatalf("invalid exact placeholder: %v", err)
	}
	state := f.anchorState(t)
	if state.Sequence() != 1 || state.JournalCount() != 1 {
		t.Fatalf("reconciled lost acknowledgement state: sequence=%d journal=%d", state.Sequence(), state.JournalCount())
	}
	if !ref.Valid() || ref.StoreID() != f.store || ref.SnapshotID() != state.CommittedSnapshotID() || ref.SnapshotID() == ([16]byte{}) {
		t.Fatalf("placeholder reference mismatch: store=%v snapshot=%v committed=%v", ref.StoreID(), ref.SnapshotID(), state.CommittedSnapshotID())
	}
	if got := f.accepted.Load() - before; got != 7 {
		t.Fatalf("connections=%d, want CLI read, writer read, reservation reconciliation read, reserve plus confirmation read, commit plus reconciliation read (7)", got)
	}
}
