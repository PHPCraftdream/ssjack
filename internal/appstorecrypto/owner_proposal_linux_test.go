package appstorecrypto

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
)

func ownerJournalSize(t *testing.T, directory *appstorefile.Directory) int64 {
	t.Helper()
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	journal, err := tx.Journal()
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	stat, err := appstorefile.Stat(journal)
	if err != nil {
		t.Fatal(err)
	}
	return stat.Size
}

func TestOwnerPrepareFailureHasNoJournalOrAnchorEffects(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		ctx, installation, directory := ownerFixture(t)
		owner := openOwnerFixture(t, ctx, installation, directory)
		baseline, err := owner.Commit(ctx)
		if err != nil {
			t.Fatal(err)
		}
		size := ownerJournalSize(t, directory)
		id, err := owner.Add("text/plain", []byte("pending synthetic value"))
		if err != nil {
			t.Fatal(err)
		}
		operation, cancel := context.WithCancel(ctx)
		failure := errors.New("synthetic intent persistence failure")
		calls := 0
		_, err = owner.CommitPrepared(operation, func(_ context.Context, proposal OwnerWriteProposal) error {
			calls++
			if proposal.Previous.Hash() != baseline.State.Hash() || proposal.TransactionID == ([16]byte{}) || proposal.SnapshotID == ([16]byte{}) || len(proposal.References) != 1 || proposal.References[0].ObjectID() != id || proposal.References[0].SnapshotID() != proposal.SnapshotID {
				t.Fatal("prepare callback did not receive the exact immutable proposal")
			}
			if cancelled {
				cancel()
				return nil
			}
			return failure
		})
		cancel()
		if calls != 1 || (cancelled && !errors.Is(err, context.Canceled)) || (!cancelled && !errors.Is(err, failure)) {
			t.Fatal("owner preparation failure was ignored")
		}
		current, readErr := writerRead(ctx, owner.transport, directory.StoreID())
		if readErr != nil || current.Hash() != baseline.State.Hash() || ownerJournalSize(t, directory) != size {
			t.Fatal("failed preparation appended a journal entry or mutated the anchor")
		}
		if len(owner.objects[id].value) == 0 {
			t.Fatal("failed preparation discarded the pending owner value")
		}
	}
}

func TestOwnerPreparedCommitMatchesPersistedProposal(t *testing.T) {
	ctx, installation, directory := ownerFixture(t)
	owner := openOwnerFixture(t, ctx, installation, directory)
	baseline, err := owner.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Add("text/plain", []byte("synthetic committed value")); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.CommitPrepared(ctx, nil); err == nil {
		t.Fatal("prepared owner commit accepted a missing persistence callback")
	}
	var prepared OwnerWriteProposal
	calls := 0
	commit, err := owner.CommitPrepared(ctx, func(ctx context.Context, proposal OwnerWriteProposal) error {
		calls++
		current, err := writerRead(ctx, owner.transport, directory.StoreID())
		if err != nil || current.Hash() != baseline.State.Hash() {
			return errors.New("reservation dispatched before durable owner intent")
		}
		prepared = proposal
		return nil
	})
	if err != nil || calls != 1 || !reflect.DeepEqual(commit.Refs, prepared.References) || commit.State.CommittedSnapshotID() != prepared.SnapshotID || commit.State.CommittedTransactionID() != prepared.TransactionID {
		t.Fatalf("commit did not match the prepared owner proposal: %v", err)
	}
}

func TestPreparedOwnerDoesNotReconcileAnOrphanBeforeIntent(t *testing.T) {
	ctx, installation, directory := ownerFixture(t)
	owner := openOwnerFixture(t, ctx, installation, directory)
	baseline, err := owner.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := newWriterEntry(baseline.State, directory.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	appendErr := tx.AppendJournal(entry.Bytes(), baseline.State.JournalCount())
	closeErr := tx.Close()
	if appendErr != nil || closeErr != nil {
		t.Fatal("orphan journal fixture could not be prepared")
	}
	size := ownerJournalSize(t, directory)
	if _, err := owner.Add("text/plain", []byte("new synthetic value")); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err = owner.CommitPrepared(ctx, func(context.Context, OwnerWriteProposal) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("owner prepared a new mutation over an unresolved orphan")
	}
	current, readErr := writerRead(ctx, owner.transport, directory.StoreID())
	if readErr != nil || current.Hash() != baseline.State.Hash() || ownerJournalSize(t, directory) != size {
		t.Fatal("prepared owner implicitly replayed or erased an old journal entry")
	}
}
