//go:build linux

package appstorewritertest

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func TestPendingCandidateWithoutIntentBurned(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("set SSJACK_TEST_FULL_KDF=1 for real Argon2id derivation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	f := makeCredentials(t)
	_, transport, _ := startService(t, f)
	store := storeID()
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	directory, err := appstorefile.Open(root, store)
	if err != nil {
		t.Fatal(err)
	}
	master := deriveMaster(t, ctx, store)
	defer master.Close()
	writer, err := appstorecrypto.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	anchorReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	anchorBefore, ok := anchorReply.State()
	if !ok || anchorBefore.Sequence() != 0 {
		t.Fatal("expected genesis anchor")
	}
	var snapshot, txn [16]byte
	snapshot[0], txn[0] = 2, 3
	entry, err := appstorejournal.NewEntry(0, snapshot, txn)
	if err != nil {
		t.Fatal(err)
	}
	proposedReq, err := appstoreanchorrequest.PlanReservation(anchorBefore, entry)
	if err != nil {
		t.Fatal(err)
	}
	proposed, ok := proposedReq.ProposedState()
	if !ok {
		t.Fatal("missing proposed reservation state")
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.AppendJournal(entry.Bytes(), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := transport.Submit(ctx, proposedReq); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	reservedReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reserved, ok := reservedReply.State()
	if !ok || reserved != proposed {
		t.Fatal("reservation did not reach proposed state")
	}
	candidate, err := tx.CreateCandidate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	marker := make([]byte, 97)
	if _, err := rand.Read(marker); err != nil {
		t.Fatal(err)
	}
	copy(marker[:16], "synthetic-invalid")
	if _, err := candidate.Write(marker); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.SyncCandidate(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	root, err = os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	directory, err = appstorefile.Open(root, store)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	defer root.Close()
	writer, err = appstorecrypto.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Recover(ctx); !errors.Is(err, appstorecrypto.ErrWriterBurned) {
		t.Fatalf("Recover error = %v, want ErrWriterBurned", err)
	}
	checkBurnState(t, ctx, rootPath, transport, reserved, snapshot, marker)
	out, err := writer.Write(ctx, nil)
	if err != nil {
		t.Fatalf("Write after burn: %v", err)
	}
	if out.State.CommittedSnapshotID() == snapshot {
		t.Fatal("writer reused burned snapshot ID")
	}
	actualReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actual, ok := actualReply.State()
	if !ok || actual.Sequence() != 1 || actual.JournalCount() != 2 {
		t.Fatalf("anchor after fresh write: %+v", actual)
	}
	checkQuarantine(t, rootPath, snapshot, marker)
	checkJournalLength(t, rootPath, 80)
}

func TestUntrustedJournalSuffixBurned(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("set SSJACK_TEST_FULL_KDF=1 for real Argon2id derivation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	f := makeCredentials(t)
	_, transport, _ := startService(t, f)
	store := storeID()
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	directory, err := appstorefile.Open(root, store)
	if err != nil {
		t.Fatal(err)
	}
	master := deriveMaster(t, ctx, store)
	defer master.Close()
	writer, err := appstorecrypto.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	anchorReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	anchorBefore, ok := anchorReply.State()
	if !ok || anchorBefore.Sequence() != 0 {
		t.Fatal("expected genesis anchor")
	}
	entry, err := appstorejournal.NewEntry(0, [16]byte{4}, [16]byte{5})
	if err != nil {
		t.Fatal(err)
	}
	proposedReq, err := appstoreanchorrequest.PlanReservation(anchorBefore, entry)
	if err != nil {
		t.Fatal(err)
	}
	reserved, ok := proposedReq.ProposedState()
	if !ok {
		t.Fatal("missing proposed reservation state")
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.AppendJournal(entry.Bytes(), 0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	root, err = os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	directory, err = appstorefile.Open(root, store)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	defer root.Close()
	writer, err = appstorecrypto.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Recover(ctx); !errors.Is(err, appstorecrypto.ErrWriterBurned) {
		t.Fatalf("Recover error = %v, want ErrWriterBurned", err)
	}
	actualReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	burned, ok := actualReply.State()
	if !ok || burned.Sequence() != 0 || burned.JournalCount() != 1 || burned != reserved {
		t.Fatalf("burned anchor state: %+v", burned)
	}
	checkJournalLength(t, rootPath, 40)
	checkNoEntries(t, rootPath, "candidates")
	checkNoEntries(t, rootPath, "snapshots")
	if _, err := os.Stat(filepath.Join(rootPath, "pointer.bin")); !os.IsNotExist(err) {
		t.Fatalf("unexpected pointer: %v", err)
	}
	out, err := writer.Write(ctx, nil)
	if err != nil {
		t.Fatalf("Write after burn: %v", err)
	}
	if out.State.CommittedSnapshotID() == entry.SnapshotID() {
		t.Fatal("writer reused burned snapshot ID")
	}
	actualReply, err = transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actual, ok := actualReply.State()
	if !ok || actual.Sequence() != 1 || actual.JournalCount() != 2 {
		t.Fatalf("anchor after fresh write: %+v", actual)
	}
	checkJournalLength(t, rootPath, 80)
}
