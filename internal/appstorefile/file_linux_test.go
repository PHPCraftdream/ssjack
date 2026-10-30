//go:build linux

package appstorefile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
	"golang.org/x/sys/unix"
)

func fileMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func testID(b byte) [16]byte { return [16]byte{15: b} }

func testRoot(t *testing.T) (*os.File, string) {
	t.Helper()
	p := t.TempDir()
	fileMust(t, os.Chmod(p, 0700))
	f, err := os.Open(p)
	fileMust(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f, p
}
func TestDirectoryJournalLockAndStaleTransaction(t *testing.T) {
	root, path := testRoot(t)
	store := testID(1)
	d, err := Open(root, store)
	fileMust(t, err)
	tx, err := d.Lock()
	fileMust(t, err)
	other, err := Open(root, store)
	fileMust(t, err)
	if _, err = other.Lock(); !errors.Is(err, ErrBusy) {
		t.Fatalf("second independent lock = %v, want ErrBusy", err)
	}
	a, err := appstorejournal.NewEntry(0, testID(2), testID(3))
	fileMust(t, err)
	rawEntry := a.Bytes()
	if err = tx.AppendJournal(rawEntry, 0); err != nil {
		t.Fatal(err)
	}
	jf, err := tx.Journal()
	fileMust(t, err)
	got, err := io.ReadAll(jf)
	_ = jf.Close()
	fileMust(t, err)
	if len(got) != 40 || string(got) != string(rawEntry[:]) {
		t.Fatalf("journal bytes = %x", got)
	}
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Journal(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale Journal = %v", err)
	}
	if err = tx.AppendJournal(rawEntry, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale append = %v", err)
	}
	tx2, err := other.Lock()
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	jf, err = tx2.Journal()
	fileMust(t, err)
	got, err = io.ReadAll(jf)
	_ = jf.Close()
	if err != nil || string(got) != string(rawEntry[:]) {
		t.Fatalf("reopened journal %x, err %v", got, err)
	}
	if err = tx2.Close(); err != nil {
		t.Fatal(err)
	}
	if err = other.Close(); err != nil {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(path, "journal.bin"), []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}
	d, err = Open(root, store)
	fileMust(t, err)
	tx, err = d.Lock()
	fileMust(t, err)
	if _, err = tx.Journal(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("partial journal = %v, want ErrInvalid", err)
	}
	_ = tx.Close()
	_ = d.Close()
}
func TestDirectoryRejectsUnsafeRootAndEntries(t *testing.T) {
	root, path := testRoot(t)
	badPath := filepath.Join(t.TempDir(), "not-private")
	if err := os.Mkdir(badPath, 0755); err != nil {
		t.Fatal(err)
	}
	bad, err := os.Open(badPath)
	fileMust(t, err)
	if _, err = Open(bad, testID(1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mode 0755 root = %v", err)
	}
	_ = bad.Close()
	externalSnapshots := filepath.Join(t.TempDir(), "snapshots")
	if err = os.Mkdir(externalSnapshots, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(externalSnapshots, filepath.Join(path, "snapshots")); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(root, testID(1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("snapshots symlink = %v", err)
	}
	if err = os.Remove(filepath.Join(path, "snapshots")); err != nil {
		t.Fatal(err)
	}
	d, err := Open(root, testID(1))
	fileMust(t, err)
	tx, err := d.Lock()
	fileMust(t, err)
	id := testID(4)
	f, err := tx.CreateCandidate(id)
	fileMust(t, err)
	ciphertext := []byte{0x91, 0x00, 0x7f, 0xe2, 0x33}
	if _, err = f.Write(ciphertext); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.CreateCandidate(id); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate candidate = %v", err)
	}
	if err = tx.SyncCandidate(id); err != nil {
		t.Fatal(err)
	}
	f, err = tx.OpenCandidate(id)
	fileMust(t, err)
	h, err := Hash(context.Background(), f, 100)
	fileMust(t, err)
	if h != sha256.Sum256(ciphertext) {
		t.Fatalf("candidate hash %x", h)
	}
	_ = f.Close()
	if err = tx.Publish(id); err != nil {
		t.Fatalf("publish: %v", err)
	}
	snap, err := tx.OpenSnapshot(id)
	fileMust(t, err)
	got, err := io.ReadAll(snap)
	if err != nil || string(got) != string(ciphertext) {
		t.Fatalf("snapshot %x, err %v", got, err)
	}
	st, err := snap.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("snapshot mode %v", st.Mode())
	}
	_ = snap.Close()
	if err = tx.Publish(id); !errors.Is(err, ErrMissing) {
		t.Fatalf("republish = %v", err)
	}
	candidatePath := filepath.Join(path, "candidates", "00000000000000000000000000000005.bin")
	f, err = tx.CreateCandidate(testID(5))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err = os.Link(candidatePath, filepath.Join(path, "candidates", "00000000000000000000000000000006.bin")); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.OpenNamed("candidates", "00000000000000000000000000000005.bin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("hardlink candidate = %v", err)
	}
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRetainIntentPointerAndHashContracts(t *testing.T) {
	root, _ := testRoot(t)
	d, err := Open(root, testID(1))
	fileMust(t, err)
	tx, err := d.Lock()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := []byte{0xa3, 0x00, 0x4b, 0xff}
	sourcePath := filepath.Join(t.TempDir(), "source")
	if err = os.WriteFile(sourcePath, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(ciphertext)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Hash(ctx, source, 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled hash = %v", err)
	}
	if err = tx.Retain(context.Background(), testID(7), testID(8), source, hash, 100); err != nil {
		t.Fatal(err)
	}
	recovery, err := tx.OpenRecovery(testID(7), testID(8))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(recovery)
	if err != nil || string(got) != string(ciphertext) {
		t.Fatalf("retained bytes %x, err %v", got, err)
	}
	st, err := recovery.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("retained mode %v", st.Mode())
	}
	_ = recovery.Close()
	if err = tx.Retain(context.Background(), testID(9), testID(10), source, [32]byte{1}, 100); err == nil {
		t.Fatal("wrong expected hash succeeded")
	}
	_ = source.Close()
	txn := testID(11)
	var raw [312]byte
	copy(raw[:8], "SSAPCMT1")
	copy(raw[8:24], txn[:])
	raw[24] = 1
	if err = tx.CreateIntent(txn, raw); err != nil {
		t.Fatal(err)
	}
	loaded, err := tx.LoadIntent(txn)
	if err != nil || loaded != raw {
		t.Fatalf("intent mismatch, err %v", err)
	}
	if err = tx.CreateIntent(txn, raw); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate intent = %v", err)
	}
	var tuple [64]byte
	binary.BigEndian.PutUint64(tuple[:8], 123)
	tuple[63] = 9
	if err = tx.Pointer(tuple); err != nil {
		t.Fatal(err)
	}
	gotTuple, err := tx.ReadPointer()
	if err != nil || gotTuple != tuple {
		t.Fatalf("pointer mismatch, err %v", err)
	}
	syncCalls := 0
	tx.state.owner.syncFD = func(fd int) error {
		if fd != tx.state.owner.dirs["intents"] {
			t.Fatal("unexpected sync descriptor")
		}
		syncCalls++
		return unix.EIO
	}
	newTxn := testID(12)
	newRaw := raw
	copy(newRaw[8:24], newTxn[:])
	err = tx.CreateIntent(newTxn, newRaw)
	tx.state.owner.syncFD = unix.Fsync
	if !errors.Is(err, ErrUncertain) || syncCalls != 1 {
		t.Fatalf("intent directory sync failure = %v, sync calls %d", err, syncCalls)
	}
	loaded, err = tx.LoadIntent(txn)
	if err != nil || loaded != raw {
		t.Fatalf("prior intent changed after create failure, err %v", err)
	}
	recovery, err = tx.OpenRecovery(testID(7), testID(8))
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(recovery)
	if err != nil || string(got) != string(ciphertext) {
		t.Fatalf("source ciphertext changed after create failure: %x, err %v", got, err)
	}
	_ = recovery.Close()
	_ = tx.Close()
	_ = d.Close()
}
