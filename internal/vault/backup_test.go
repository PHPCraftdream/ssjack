package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotationRestartUsesFreshSessionRevisionForVerifiedAndCommittedRecovery(t *testing.T) {
	public, private := rotationTestIdentity(t)
	defer clear(public)
	defer clear(private)
	for _, phase := range []string{RotationVerified, RotationCommitted} {
		t.Run(phase, func(t *testing.T) {
			v, server := directoryFixture(t)
			old := ownTarget(v.Targets["production"])
			defer clear(old.PrivateKey)
			journal := &RotationJournal{
				ID: "0102030405060708090a0b0c0d0e0f10", PlanID: 4, BaseRevision: 7,
				Phase: phase, ServerID: server, Account: "main", Profile: "production",
				Original: ownTarget(old), NewPrivate: append([]byte(nil), private...),
				NewPublic: append([]byte(nil), public...), OldPublic: testPublic(t, old.PrivateKey),
			}
			if phase == RotationCommitted {
				current := v.Targets["production"]
				clear(current.PrivateKey)
				current.PrivateKey = append([]byte(nil), private...)
				v.Targets["production"] = current
				journal.CommitRevision = 0
			}
			v.Rotation = journal
			payload, err := marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := unmarshal(payload)
			clear(payload)
			if err != nil {
				t.Fatal(err)
			}
			digest := [32]byte{1}
			session := newSession(restarted, func(context.Context, []byte) error { return nil }, func() {})
			session.saveDigest = func() [32]byte { return digest }
			session.savedCipher = digest
			defer session.Discard()
			if status := session.Status(); status.Revision != 0 || status.SavedRevision != 0 {
				t.Fatal("restarted session did not begin at revision zero")
			}
			if phase == RotationVerified {
				if err := session.CommitRotationAt(0, 4); err != nil {
					t.Fatalf("verified recovery rejected fresh session revision: %v", err)
				}
				if err := session.Flush(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := session.CompleteRotationAt(1, 4, digest); err != nil {
					t.Fatalf("committed recovery rejected fresh session revision: %v", err)
				}
			} else if err := session.CompleteRotationAt(0, 4, digest); err != nil {
				t.Fatalf("already-committed recovery rejected fresh session revision: %v", err)
			}
			if err := session.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			info, err := session.RotationSnapshot()
			if err != nil || info.Phase != RotationComplete {
				t.Fatalf("recovery did not complete: phase=%q err=%v", info.Phase, err)
			}
		})
	}
}

func TestArchiveRotationCopiesSavedCiphertextAndQueuesReceiptTombstone(t *testing.T) {
	state, server := directoryFixture(t)
	old := ownTarget(state.Targets["production"])
	defer clear(old.PrivateKey)
	public, private := rotationTestIdentity(t)
	defer clear(public)
	defer clear(private)
	current := state.Targets["production"]
	clear(current.PrivateKey)
	current.PrivateKey = append([]byte(nil), private...)
	state.Targets["production"] = current
	state.Rotation = &RotationJournal{
		ID: "0102030405060708090a0b0c0d0e0f10", PlanID: 3, BaseRevision: 7,
		CommitRevision: 0,
		Phase:          RotationComplete, ServerID: server, Account: "main", Profile: "production",
		Original: old, NewPrivate: append([]byte(nil), private...), NewPublic: append([]byte(nil), public...),
		OldPublic:    testPublic(t, old.PrivateKey),
		CommitDigest: "0101010101010101010101010101010101010101010101010101010101010101",
	}
	path := filepath.Join(t.TempDir(), "vault")
	ciphertext := []byte("synthetic saved ciphertext from completed rotation")
	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	currentDigest := sha256.Sum256(ciphertext)
	currentHex := fmt.Sprintf("%x", currentDigest)
	if currentHex == state.Rotation.CommitDigest {
		t.Fatal("test requires historical commit proof to differ from current ciphertext")
	}
	var savedPayload []byte
	session := newSession(state, func(_ context.Context, payload []byte) error {
		clear(savedPayload)
		savedPayload = append(savedPayload, payload...)
		return nil
	}, func() {})
	session.revision, session.saved = 0, 0
	session.savedCipher = currentDigest
	defer session.Discard()
	defer clear(savedPayload)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id := state.Rotation.ID
	for _, request := range []struct {
		revision uint64
		planID   uint64
		id       string
	}{{1, 3, id}, {0, 2, id}, {0, 3, "0102030405060708090a0b0c0d0e0f11"}} {
		if _, err := session.ArchiveRotationAt(ctx, path, request.revision, request.planID, request.id); !errors.Is(err, ErrOwnerRevision) {
			t.Fatal("stale revision or mismatched journal identity was archived")
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("rejected archive requests changed the file inventory")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := session.ArchiveRotationAt(cancelled, path, 0, 3, id); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled archive request was accepted")
	}
	entries, err = os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("cancelled archive request changed the file inventory")
	}
	info, err := session.ArchiveRotationAt(ctx, path, 0, 3, id)
	if err != nil {
		t.Fatal(err)
	}
	if info.Phase != RotationArchived || info.ID != id || info.PlanID != 3 || info.ServerID != server || info.Account != "main" || info.Profile != "production" || info.RecoveryPath == "" || info.RecoveryDigest != currentHex {
		t.Fatal("archive receipt lost stable rotation identity or current ciphertext digest")
	}
	archive, err := readEncoded(info.RecoveryPath)
	if err != nil || !bytes.Equal(archive, ciphertext) {
		t.Fatal("encrypted archive does not match the exact saved database ciphertext")
	}
	if err := session.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	persisted, err := unmarshal(savedPayload)
	if err != nil {
		t.Fatal(err)
	}
	defer persisted.Close()
	journal := persisted.Rotation
	if journal == nil || journal.Phase != RotationArchived || journal.ID != id || journal.PlanID != 3 || journal.ServerID != server || journal.Account != "main" || journal.Profile != "production" || journal.RecoveryPath != info.RecoveryPath || journal.RecoveryDigest != currentHex || !rotationTargetEmpty(journal.Original) || len(journal.NewPrivate)+len(journal.NewPublic)+len(journal.OldPublic) != 0 {
		t.Fatal("queued tombstone did not retain the archive receipt and clear private material")
	}
	if got, err := readEncoded(path); err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatal("archival changed the current live database ciphertext")
	}
	if _, err := session.ArchiveRotationAt(ctx, path, 0, 3, id); !errors.Is(err, ErrOwnerRevision) {
		t.Fatal("repeat archival of the tombstone was accepted")
	}
	entries, err = os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 2 {
		t.Fatal("stale archive request changed the file inventory")
	}
}

func TestRestoreRetainsPreviousEncryptedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	previous := []byte("opaque previous ciphertext")
	replacement := []byte("opaque replacement ciphertext")
	if err := commit(path, previous, nil); err != nil {
		t.Fatal(err)
	}
	backup, err := restoreVerified(context.Background(), path, replacement, previous)
	if err != nil || backup == "" {
		t.Fatalf("restore: %q %v", backup, err)
	}
	for file, want := range map[string][]byte{path: replacement, backup: previous} {
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encrypted bytes changed: %s", filepath.Base(file))
		}
	}
	if _, err := restoreVerified(context.Background(), path, previous, previous); err == nil {
		t.Fatal("stale restore overwrote the new revision")
	}
}

func TestRestoreFailureAndCancellationPreserveCurrentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	previous := []byte("opaque ciphertext")
	if err := commit(path, previous, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := restoreVerified(ctx, path, []byte("replacement"), previous); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled restore: %v", err)
	}
	if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	backup, err := restoreVerified(context.Background(), path, []byte("replacement"), previous)
	if err == nil || backup == "" {
		t.Fatal("failed commit did not retain recovery snapshot")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, previous) {
		t.Fatal("failed restore modified the working database")
	}
	got, readErr = os.ReadFile(backup)
	if readErr != nil || !bytes.Equal(got, previous) {
		t.Fatal("failed restore lost the previous encrypted data")
	}
}

func TestCancelledWritesDoNotDeriveOrCreateFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v := New()
	defer v.Close()
	if err := CreateContext(ctx, path, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled creation was accepted")
	}
	if err := SaveContext(ctx, path, v, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled save was accepted")
	}
	if err := Backup(ctx, "missing", path, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled backup read or wrote credentials")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("cancelled operation created a database")
	}
}

func TestSnapshotRejectsRevisionChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	data := []byte("authenticated ciphertext fixture")
	if err := commit(path, data, nil); err != nil {
		t.Fatal(err)
	}
	v := New()
	defer v.Close()
	v.revision = sha256.Sum256(data)
	backup, err := Snapshot(path, v)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(backup); err != nil || !bytes.Equal(got, data) {
		t.Fatal("snapshot bytes changed")
	}
	if err := os.WriteFile(path, []byte("newer revision"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Snapshot(path, v); err == nil {
		t.Fatal("unauthenticated newer revision was snapshotted")
	}
}
