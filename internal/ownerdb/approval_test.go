package ownerdb

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func setVerifier(t *testing.T, m *Manager, hash string, verifyErr error) {
	t.Helper()
	if err := m.SetDescriptorVerifier(func(string) (string, error) { return hash, verifyErr }); err != nil {
		t.Fatal(err)
	}
}

func approveMutation(name, path, hash string) ApprovalMutation {
	return ApprovalMutation{Kind: "approve", Name: name, Path: path, Hash: hash}
}

func revokeMutation(name, path, hash string) ApprovalMutation {
	return ApprovalMutation{Kind: "revoke", Name: name, Hash: hash, Replaces: hash} // the wire carries no path on revoke
}

func snapshotFiles(t *testing.T, vaultPath string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(vaultPath))
	if err != nil {
		t.Fatal(err)
	}
	prefix, suffix := filepath.Base(vaultPath)+"."+approvalSnapshotLabel+"-", ".ssjack.ktav"
	var files []string
	for _, entry := range entries {
		if name := entry.Name(); strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files
}

// clearSnapshots deletes evidence snapshots only; it never touches the vault file or session.
func clearSnapshots(t *testing.T, vaultPath string) {
	t.Helper()
	for _, name := range snapshotFiles(t, vaultPath) {
		if err := os.Remove(filepath.Join(filepath.Dir(vaultPath), name)); err != nil {
			t.Fatal(err)
		}
	}
}

// makeStandins writes n stand-in snapshot files; file i gets the modification time stamp(i).
func makeStandins(t *testing.T, vaultPath string, n int, stamp func(i int) time.Time) []string {
	t.Helper()
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%s.%s-%02d-standin.ssjack.ktav", filepath.Base(vaultPath), approvalSnapshotLabel, i)
		file := filepath.Join(filepath.Dir(vaultPath), names[i])
		if err := os.WriteFile(file, []byte("stand-in"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, stamp(i), stamp(i)); err != nil {
			t.Fatal(err)
		}
	}
	return names
}

func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func holdSaveLock(t *testing.T, vaultPath string) {
	t.Helper()
	if err := os.WriteFile(vaultPath+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(vaultPath + ".lock") })
}
func fakeDescriptor(path string) (string, error) {
	if hash, ok := fakeHashes[path]; ok {
		return hash, nil
	}
	return "", errors.New("descriptor missing")
}

// waitDurable polls (bounded): a manager retry is asynchronous, and Session.Flush would return the stale save error before the worker clears it.
func waitDurable(t *testing.T, m *Manager) {
	t.Helper()
	flakediag.WaitFor(t, "database becomes durable", 30*time.Second, func() (string, bool) {
		status := m.Status().Database
		return fmt.Sprintf("revision=%d saved=%d pending=%v err=%v", status.Revision, status.SavedRevision, status.Pending, status.Err), !status.Pending && status.Err == nil && status.Revision == status.SavedRevision
	})
}

func approvalHash(seed byte) string { return fmt.Sprintf("%064x", seed) }

func approvalNames(t *testing.T, m *Manager) []string {
	t.Helper()
	metadata, err := m.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(metadata.Approvals))
	for _, approval := range metadata.Approvals {
		names = append(names, approval.Name)
	}
	return names
}

func hasName(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}

// unchangedApproval asserts a refused composite left the vault, revision and approval list as they were.
func unchangedApproval(t *testing.T, m *Manager, path string, before [32]byte, revision uint64, count int, message string) {
	t.Helper()
	if len(snapshotFiles(t, path)) != 0 || fileDigest(t, path) != before || m.Status().Database.Revision != revision || len(approvalNames(t, m)) != count {
		t.Fatal(message)
	}
}

func TestApprovalVerifyRefusals(t *testing.T) {
	m, path, _ := sharedManager(t)
	dir := filepath.Dir(path)
	t.Run("unconfigured keeper refuses", func(t *testing.T) {
		before, revision, count := fileDigest(t, path), m.Status().Database.Revision, len(approvalNames(t, m))
		mutationPath := filepath.Join(dir, "app-v0")
		if err := m.ApproveWithSnapshot(context.Background(), revision, approveMutation("app-v0", mutationPath, approvalHash(1))); !errors.Is(err, ErrApprovalReview) {
			t.Fatalf("unconfigured verifier error = %v", err)
		}
		unchangedApproval(t, m, path, before, revision, count, "unconfigured keeper changed approval state")
		// This zero value is a throwaway guard check and is never used for approvals.
		if err := (&Manager{}).SetDescriptorVerifier(nil); err == nil {
			t.Fatal("nil verifier replacement succeeded")
		}
	})
	if err := m.SetDescriptorVerifier(fakeDescriptor); err != nil {
		t.Fatal(err)
	}
	t.Run("verifier error refuses with review", func(t *testing.T) {
		before, revision, count := fileDigest(t, path), m.Status().Database.Revision, len(approvalNames(t, m))
		mutationPath := filepath.Join(dir, "app-v1")
		if err := m.ApproveWithSnapshot(context.Background(), revision, approveMutation("app-v1", mutationPath, approvalHash(1))); !errors.Is(err, ErrApprovalReview) {
			t.Fatalf("verifier error = %v", err)
		}
		unchangedApproval(t, m, path, before, revision, count, "verifier error changed approval state")
	})
	t.Run("mismatch refuses with review", func(t *testing.T) {
		mutationPath := filepath.Join(dir, "app-v2")
		before, revision, count := fileDigest(t, path), m.Status().Database.Revision, len(approvalNames(t, m))
		fakeHashes[mutationPath] = approvalHash(9)
		mutation := approveMutation("app-v2", mutationPath, approvalHash(1))
		if err := m.ApproveWithSnapshot(context.Background(), revision, mutation); !errors.Is(err, ErrApprovalReview) {
			t.Fatalf("mismatch error = %v", err)
		}
		unchangedApproval(t, m, path, before, revision, count, "mismatch changed approval state")
		fakeHashes[mutationPath] = approvalHash(1)
		if err := m.ApproveWithSnapshot(context.Background(), revision, mutation); err != nil {
			t.Fatal(err)
		}
		if err := m.SetDescriptorVerifier(fakeDescriptor); err == nil {
			t.Fatal("verifier replacement after approval succeeded")
		}
		if len(snapshotFiles(t, path)) != 1 || fileDigest(t, path) == before {
			t.Fatal("first approval was not persisted with one snapshot")
		}
	})
}
func TestApprovalSnapshotThenApplyAtomic(t *testing.T) {
	m, path, _ := sharedManager(t)
	clearSnapshots(t, path)
	dir := filepath.Dir(path)
	pathA, pathB := filepath.Join(dir, "app-a1"), filepath.Join(dir, "app-a2")
	fakeHashes[pathA], fakeHashes[pathB] = approvalHash(1), approvalHash(2)
	waitDurable(t, m)
	status := m.Status().Database
	expected, before, baseline := status.Revision, fileDigest(t, path), len(approvalNames(t, m))
	if status.Revision != status.SavedRevision || status.Pending || status.Err != nil {
		t.Fatalf("database not saved before the race: %+v", status)
	}
	loser := make(chan error, 1)
	go func() {
		loser <- m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-a2", pathB, approvalHash(2)))
	}()
	err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-a1", pathA, approvalHash(1)))
	loserErr := <-loser
	if (err == nil) == (loserErr == nil) {
		t.Fatalf("composite outcomes = %v, %v", err, loserErr)
	}
	if err != nil && !errors.Is(err, vault.ErrOwnerRevision) || loserErr != nil && !errors.Is(loserErr, vault.ErrOwnerRevision) {
		t.Fatalf("losing composite error = %v, %v", err, loserErr)
	}
	files := snapshotFiles(t, path)
	if len(files) != 1 || fileDigest(t, filepath.Join(dir, files[0])) != before {
		t.Fatal("snapshot did not preserve pre-write ciphertext")
	}
	if fileDigest(t, path) == before {
		t.Fatal("database ciphertext did not change")
	}
	status = m.Status().Database
	names := approvalNames(t, m)
	winner, lost := "app-a1", "app-a2"
	if err != nil {
		winner, lost = lost, winner
	}
	if status.Pending || status.Err != nil || status.Revision != expected+1 || status.SavedRevision != expected+1 || len(names) != baseline+1 || !hasName(names, winner) || hasName(names, lost) {
		t.Fatalf("unexpected composite result: %+v, approvals %v", status, names)
	}
}

func TestApprovalSnapshotRetentionBound(t *testing.T) {
	m, path, _ := sharedManager(t)
	var passZeroSnapshot string
	dir := filepath.Dir(path)
	t.Run("retains newest snapshots", func(t *testing.T) {
		clearSnapshots(t, path)
		expected := m.Status().Database.Revision
		baseTime := time.Now()
		standins := makeStandins(t, path, 10, func(i int) time.Time { return baseTime.Add(-time.Duration(100-i) * time.Hour) })
		for i := 0; i < 2; i++ {
			name := fmt.Sprintf("app-r%d", i)
			p := filepath.Join(dir, name)
			hash := approvalHash(byte(i + 1))
			fakeHashes[p] = hash
			if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation(name, p, hash)); err != nil {
				t.Fatalf("pass %d: %v", i, err)
			}
			expected++
			files := snapshotFiles(t, path)
			if len(files) != 10 {
				t.Fatalf("pass %d snapshot count = %d", i, len(files))
			}
			if i == 0 {
				for _, file := range files {
					if !strings.Contains(file, "-standin.") {
						passZeroSnapshot = file
						break
					}
				}
				if passZeroSnapshot == "" {
					t.Fatal("pass 0 real snapshot missing")
				}
			} else if _, err := os.Stat(filepath.Join(dir, passZeroSnapshot)); err != nil {
				t.Fatalf("pass 0 real snapshot missing after pass 1: %v", err)
			}
			for j, name := range standins {
				_, statErr := os.Stat(filepath.Join(dir, name))
				removed := j <= i
				if removed && statErr == nil {
					t.Fatalf("oldest stand-in %d remains after pass %d", j, i)
				}
				if !removed && statErr != nil {
					t.Fatalf("newer stand-in %d missing after pass %d: %v", j, i, statErr)
				}
			}
		}
		waitDurable(t, m)
	})
	t.Run("approve revoke round trip", func(t *testing.T) {
		name, p := "app-rr", filepath.Join(dir, "app-rr")
		fakeHashes[p] = approvalHash(1)
		expected, baseline := m.Status().Database.Revision, len(approvalNames(t, m))
		if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation(name, p, approvalHash(1))); err != nil {
			t.Fatal(err)
		}
		expected++
		names := approvalNames(t, m)
		if len(names) != baseline+1 || !hasName(names, name) || m.Status().Database.Revision != expected || len(snapshotFiles(t, path)) != 10 {
			t.Fatal("approve round trip state mismatch")
		}
		if err := m.ApproveWithSnapshot(context.Background(), expected, revokeMutation(name, p, approvalHash(1))); err != nil {
			t.Fatal(err)
		}
		expected++
		waitDurable(t, m)
		names = approvalNames(t, m)
		if len(names) != baseline || hasName(names, name) || m.Status().Database.Revision != expected || len(snapshotFiles(t, path)) != 10 {
			t.Fatal("revoke round trip state mismatch")
		}
	})
	t.Run("prune failure refuses", func(t *testing.T) {
		// Start with only the nine stand-ins so the oldest blocker is the sole prune candidate.
		for _, name := range snapshotFiles(t, path) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		baseTime := time.Now()
		makeStandins(t, path, 9, func(i int) time.Time { return baseTime.Add(time.Duration(i) * time.Hour) })
		blocker := filepath.Join(dir, fmt.Sprintf("%s.%s-00-blocker.ssjack.ktav", filepath.Base(path), approvalSnapshotLabel))
		if err := os.Mkdir(blocker, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blocker, "retain"), []byte("stand-in"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(blocker) })
		oldest := baseTime.Add(-time.Hour)
		if err := os.Chtimes(blocker, oldest, oldest); err != nil {
			t.Fatal(err)
		}
		before, revision := fileDigest(t, path), m.Status().Database.Revision
		p := filepath.Join(dir, "app-prune")
		fakeHashes[p] = approvalHash(1)
		if err := m.ApproveWithSnapshot(context.Background(), revision, approveMutation("app-prune", p, approvalHash(1))); err == nil || errors.Is(err, vault.ErrOwnerRevision) || errors.Is(err, ErrApprovalReview) || errors.Is(err, ErrPending) {
			t.Fatalf("prune failure error = %v", err)
		}
		status := m.Status().Database
		if len(snapshotFiles(t, path)) != 10 || fileDigest(t, path) != before || status.Revision != revision {
			t.Fatal("prune failure changed vault state or created a snapshot")
		}
	})
}

func TestApprovalSnapshotSucceededEditRejected(t *testing.T) {
	m, path, _ := sharedManager(t)
	clearSnapshots(t, path)
	dir := filepath.Dir(path)
	appPath := filepath.Join(dir, "app-e-shared")
	fakeHashes[appPath] = approvalHash(1)
	expected, baseline := m.Status().Database.Revision, len(approvalNames(t, m))
	if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-e1", appPath, approvalHash(1))); err != nil {
		t.Fatal(err)
	}
	firstDigest := fileDigest(t, path)
	expected++
	if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-e2", appPath, approvalHash(1))); err == nil || err.Error() != "another approved application already uses this path" {
		t.Fatalf("unexpected path-conflict error: %v", err)
	}
	names := approvalNames(t, m)
	if len(snapshotFiles(t, path)) != 2 || len(names) != baseline+1 || !hasName(names, "app-e1") || hasName(names, "app-e2") || fileDigest(t, path) != firstDigest || m.Status().Database.Revision != expected {
		t.Fatal("rejected edit did not retain only the first approval")
	}
}

func TestApprovalSaveSucceededReplyLost(t *testing.T) {
	// Proves only that a durable success is readable afterwards and that one composite yields exactly one approval and snapshot; it does not model a lost reply (the no-replay rule is pinned in internal/ownerrpc/exchange_test.go).
	m, path, _ := sharedManager(t)
	dir := filepath.Dir(path)
	p := filepath.Join(dir, "app-reply")
	fakeHashes[p] = approvalHash(1)
	before, expected := fileDigest(t, path), m.Status().Database.Revision
	beforeFiles := len(snapshotFiles(t, path))
	beforeMetadata, err := m.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-reply", p, approvalHash(1))); err != nil {
		t.Fatal(err)
	}
	metadata, metadataErr := m.Metadata()
	status := m.Status().Database
	found := false
	for _, approval := range metadata.Approvals {
		if approval.Name == "app-reply" && approval.Path == p && approval.Hash == approvalHash(1) {
			found = true
		}
	}
	if metadataErr != nil || status.SavedRevision != expected+1 || status.Revision != expected+1 || len(metadata.Approvals) != len(beforeMetadata.Approvals)+1 || !found || fileDigest(t, path) == before || len(snapshotFiles(t, path)) != beforeFiles+1 {
		t.Fatal("durable approval state was not confirmed")
	}
}

func TestApprovalSnapshotFailureKeepsVaultUnchanged(t *testing.T) {
	m, path, _ := openCopiedManager(t)
	setVerifier(t, m, approvalHash(1), nil)
	if err := os.WriteFile(path, []byte("corrupted ciphertext fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	corrupted, expected := fileDigest(t, path), m.Status().Database.Revision
	err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app", filepath.Join(filepath.Dir(path), "app"), approvalHash(1)))
	status := m.Status().Database
	metadata, metadataErr := m.Metadata()
	if err == nil || len(snapshotFiles(t, path)) != 0 || fileDigest(t, path) != corrupted || status.Revision != expected || status.SavedRevision != expected || status.Err != nil || status.Pending || metadataErr != nil || len(metadata.Approvals) != 0 {
		t.Fatal("snapshot failure changed the live approval state")
	}
}

func TestApprovalEditAppliedThenSaveFailed(t *testing.T) {
	m, path, _ := openCopiedManagerWithCleanup(t, false)
	restartBeforeSaveManager = m
	setVerifier(t, m, approvalHash(1), nil)
	holdSaveLock(t, path)
	before, expected := fileDigest(t, path), m.Status().Database.Revision
	err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app", filepath.Join(filepath.Dir(path), "app"), approvalHash(1)))
	status := m.Status().Database
	metadata, metadataErr := m.Metadata()
	if err == nil || status.Revision != expected+1 || !status.Pending || status.Err == nil || metadataErr != nil || len(metadata.Approvals) != 1 || fileDigest(t, path) != before || len(snapshotFiles(t, path)) != 1 {
		t.Fatal("save failure rolled back or persisted the applied approval")
	}
}
func TestApprovalRestartBeforeSave(t *testing.T) {
	// Depends on TestApprovalEditAppliedThenSaveFailed running first in source order; its manager is applied in memory but not durable.
	m := restartBeforeSaveManager
	if m == nil {
		t.Skip("needs TestApprovalEditAppliedThenSaveFailed in the same run")
	}
	restartBeforeSaveManager = nil
	path := m.path
	m.Discard()
	reopened, err := Open(context.Background(), path, []byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	reopenedManager = reopened
	status := reopened.Status().Database
	metadata, metadataErr := reopened.Metadata()
	if status.Revision != status.SavedRevision || metadataErr != nil || len(metadata.Approvals) != 0 || len(snapshotFiles(t, path)) != 1 {
		t.Fatal("restart before save did not reopen the prior state")
	}
}
func TestApprovalTimeoutAfterEnqueue(t *testing.T) {
	// Proves operation-failure after enqueue using the .lock seam to make save fail. It cannot pause the worker mid-save, so the timeout branch is not exercised; a queued save may complete after explicit retry, never by replaying the operation.
	// Runs on the manager reopened by TestApprovalRestartBeforeSave (prior durable state, no approvals).
	m := reopenedManager
	if m == nil {
		t.Skip("needs TestApprovalRestartBeforeSave in the same run")
	}
	path := m.path
	setVerifier(t, m, approvalHash(1), nil)
	holdSaveLock(t, path)
	before, expected := fileDigest(t, path), m.Status().Database.Revision
	err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app", filepath.Join(filepath.Dir(path), "app"), approvalHash(1)))
	status := m.Status().Database
	metadata, metadataErr := m.Metadata()
	if err == nil || errors.Is(err, vault.ErrOwnerRevision) || errors.Is(err, ErrApprovalReview) || errors.Is(err, ErrPending) {
		t.Fatalf("save failure outcome class = %v", err)
	}
	if status.Revision != expected+1 || !status.Pending || metadataErr != nil || len(metadata.Approvals) != 1 || fileDigest(t, path) != before {
		t.Fatal("save failure after enqueue did not preserve the applied pending state")
	}
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := m.RetryDatabaseAt(expected + 1); err != nil {
		t.Fatal(err)
	}
	waitDurable(t, m)
	metadata, metadataErr = m.Metadata()
	if metadataErr != nil || len(metadata.Approvals) != 1 || metadata.Approvals[0].Hash != approvalHash(1) || m.Status().Database.Revision != expected+1 || fileDigest(t, path) == before {
		t.Fatal("retry failed to durably persist exactly one approval")
	}
}

func TestApprovalReplacesHashPreflight(t *testing.T) {
	m, path, _ := sharedManager(t)
	dir := filepath.Dir(path)
	run := func(t *testing.T, name string, replacement string, wantSuccess bool) {
		t.Helper()
		p := filepath.Join(dir, name)
		oldHash, newHash := approvalHash(61), approvalHash(62)
		fakeHashes[p] = oldHash
		expected := m.Status().Database.Revision
		beforeSnapshots := len(snapshotFiles(t, path))
		if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation(name, p, oldHash)); err != nil {
			t.Fatal(err)
		}
		if m.Status().Database.Revision != expected+1 || len(snapshotFiles(t, path)) != beforeSnapshots+1 {
			t.Fatal("initial approval did not add one revision and snapshot")
		}
		beforeDigest, revision := fileDigest(t, path), m.Status().Database.Revision
		beforeSnapshots = len(snapshotFiles(t, path))
		fakeHashes[p] = newHash
		mutation := approveMutation(name, p, newHash)
		mutation.Replaces = replacement
		// manager.go:226-235 rejects mismatched live hashes before snapshotting at 191-195.
		err := m.ApproveWithSnapshot(context.Background(), revision, mutation)
		if !wantSuccess {
			if !errors.Is(err, ErrApprovalReview) || len(snapshotFiles(t, path)) != beforeSnapshots || m.Status().Database.Revision != revision || fileDigest(t, path) != beforeDigest {
				t.Fatalf("refused replacement changed state: err=%v", err)
			}
			return
		}
		metadata, metadataErr := m.Metadata()
		found := false
		for _, approval := range metadata.Approvals {
			if approval.Name == name && approval.Hash == newHash {
				found = true
			}
		}
		if err != nil || metadataErr != nil || m.Status().Database.Revision != revision+1 || len(snapshotFiles(t, path)) != beforeSnapshots+1 || !found {
			t.Fatalf("replacement result err=%v metadata=%v", err, metadataErr)
		}
	}
	t.Run("empty replace hash over existing record refused before snapshot", func(t *testing.T) { run(t, "preflight-empty", "", false) })
	t.Run("wrong replace hash refused before snapshot", func(t *testing.T) { run(t, "preflight-wrong", approvalHash(63), false) })
	t.Run("correct replace hash succeeds with exactly one snapshot", func(t *testing.T) { run(t, "preflight-correct", approvalHash(61), true) })
}

func TestApprovalFirstApprovalWithoutReplacesSucceeds(t *testing.T) {
	m, path, _ := sharedManager(t)
	name := "preflight-first"
	p := filepath.Join(filepath.Dir(path), name)
	hash := approvalHash(64)
	fakeHashes[p] = hash
	revision, snapshots := m.Status().Database.Revision, len(snapshotFiles(t, path))
	if err := m.ApproveWithSnapshot(context.Background(), revision, approveMutation(name, p, hash)); err != nil {
		t.Fatal(err)
	}
	metadata, err := m.Metadata()
	found := false
	for _, approval := range metadata.Approvals {
		if approval.Name == name && approval.Hash == hash {
			found = true
		}
	}
	if err != nil || !found || m.Status().Database.Revision != revision+1 || len(snapshotFiles(t, path)) != snapshots+1 {
		t.Fatalf("first approval result: metadata=%v", err)
	}
}

// TestApprovalRestartAfterDurableSave reopens the shared manager's vault, so it must stay the last test that uses it.
func TestApprovalRestartAfterDurableSave(t *testing.T) {
	m, path, password := sharedManager(t)
	_ = m.SetDescriptorVerifier(fakeDescriptor) // fails once an earlier scenario already approved; needed only when run alone
	dir := filepath.Dir(path)
	appPath := filepath.Join(dir, "app-rd")
	fakeHashes[appPath] = approvalHash(1)
	expected := m.Status().Database.Revision
	if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-rd", appPath, approvalHash(1))); err != nil {
		t.Fatal(err)
	}
	status := m.Status().Database
	if status.Revision != expected+1 || status.SavedRevision != expected+1 {
		t.Fatal("approval was not durable before restart")
	}
	want := approvalNames(t, m)
	m.Discard()
	shared, sharedErr = nil, errors.New("shared manager was discarded by the restart scenario")
	reopened, err := Open(context.Background(), path, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Discard)
	metadata, metadataErr := reopened.Metadata()
	status = reopened.Status().Database
	got := approvalNames(t, reopened)
	exact := slices.ContainsFunc(metadata.Approvals, func(a vault.Approval) bool {
		return a.Name == "app-rd" && a.Path == appPath && a.Hash == approvalHash(1)
	})
	sort.Strings(want)
	sort.Strings(got)
	if metadataErr != nil || !exact || strings.Join(got, ",") != strings.Join(want, ",") || status.Revision != status.SavedRevision || len(snapshotFiles(t, path)) == 0 {
		t.Fatal("restart after durable save lost an approval or its evidence snapshot")
	}
}
