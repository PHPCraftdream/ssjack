package appstorefilecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func id(value byte) [16]byte { return [16]byte{15: value} }
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) (*ownerfs.Root, *appstorefile.Directory) {
	t.Helper()
	root, err := ownerfs.MakeRoot(filepath.Join(t.TempDir(), "store"))
	must(t, err)
	t.Cleanup(func() { root.Close() })
	file, err := root.File()
	must(t, err)
	directory, err := appstorefile.Open(file, id(1))
	file.Close()
	must(t, err)
	t.Cleanup(func() { directory.Close() })
	return root, directory
}
func candidate(t *testing.T, tx *appstorefile.Transaction, snapshot [16]byte, data []byte) {
	t.Helper()
	file, err := tx.CreateCandidate(snapshot)
	must(t, err)
	_, err = file.Write(data)
	must(t, err)
	must(t, file.Close())
	must(t, tx.SyncCandidate(snapshot))
}
func contents(t *testing.T, file *os.File, err error, want []byte) {
	t.Helper()
	must(t, err)
	actual, err := io.ReadAll(file)
	must(t, err)
	must(t, file.Close())
	if !bytes.Equal(actual, want) {
		t.Fatal("native record bytes changed")
	}
}
func TestNativeRecordTransactionPublicationAndRecovery(t *testing.T) {
	root, directory := fixture(t)
	// Installation ownership and data transactions are distinct locks.
	unlock, err := root.LockName(".lock")
	must(t, err)
	defer unlock()
	tx, err := directory.Lock()
	must(t, err)
	defer tx.Close()
	if directory.StoreID() != id(1) {
		t.Fatal("store binding changed")
	}
	if err := directory.Close(); !errors.Is(err, appstorefile.ErrBusy) {
		t.Fatal("active transaction did not retain directory")
	}
	file, err := root.File()
	must(t, err)
	other, err := appstorefile.Open(file, id(1))
	file.Close()
	must(t, err)
	defer other.Close()
	if duplicate, err := other.Lock(); !errors.Is(err, appstorefile.ErrBusy) {
		if duplicate != nil {
			duplicate.Close()
		}
		t.Fatal("independent transaction acquired writer lock")
	}
	data := []byte("synthetic encrypted candidate")
	candidate(t, tx, id(2), data)
	if file, err := tx.CreateCandidate(id(2)); !errors.Is(err, appstorefile.ErrExists) {
		if file != nil {
			file.Close()
		}
		t.Fatal("candidate creation overwrote ciphertext")
	}
	must(t, tx.Publish(id(2)))
	candidate(t, tx, id(2), []byte("synthetic conflicting candidate"))
	if err := tx.Publish(id(2)); !errors.Is(err, appstorefile.ErrExists) {
		t.Fatal("publication overwrote snapshot")
	}
	must(t, tx.Quarantine(id(2)))
	must(t, tx.Quarantine(id(2)))
	snapshot, err := tx.OpenSnapshot(id(2))
	must(t, err)
	must(t, tx.Retain(context.Background(), id(2), id(3), snapshot, sha256.Sum256(data), 4096))
	must(t, snapshot.Close())
	recovered, err := tx.OpenRecovery(id(2), id(3))
	contents(t, recovered, err, data)
	var entry [40]byte
	copy(entry[8:24], idBytes(2))
	copy(entry[24:], idBytes(3))
	must(t, tx.AppendJournal(entry, 0))
	if err := tx.AppendJournal(entry, 0); !errors.Is(err, appstorefile.ErrChanged) {
		t.Fatal("stale journal count admitted")
	}
	binary.BigEndian.PutUint64(entry[:8], 1)
	must(t, tx.AppendJournal(entry, 1))
	must(t, tx.SyncJournal())
	journal, err := tx.Journal()
	must(t, err)
	raw, err := io.ReadAll(journal)
	must(t, err)
	must(t, journal.Close())
	if len(raw) != 80 || !bytes.Equal(raw[40:], entry[:]) {
		t.Fatal("journal bytes changed")
	}
	var intent [312]byte
	copy(intent[:8], "SSAPCMT1")
	copy(intent[8:24], idBytes(3))
	intent[311] = 9
	must(t, tx.CreateIntent(id(3), intent))
	if err := tx.CreateIntent(id(3), intent); !errors.Is(err, appstorefile.ErrExists) {
		t.Fatal("intent overwritten")
	}
	actual, err := tx.LoadIntent(id(3))
	must(t, err)
	if actual != intent {
		t.Fatal("intent changed")
	}
	must(t, tx.Entries("intents", func(string) error {
		reloaded, err := tx.LoadIntent(id(3))
		if err != nil {
			return err
		}
		if reloaded != intent {
			return appstorefile.ErrChanged
		}
		return nil
	}))
	var pointer [64]byte
	pointer[0] = 1
	must(t, tx.Pointer(pointer))
	pointer[63] = 7
	must(t, tx.Pointer(pointer))
	got, err := tx.ReadPointer()
	must(t, err)
	if got != pointer {
		t.Fatal("explicit pointer replacement failed")
	}
	count := 0
	must(t, tx.Entries("snapshots", func(string) error { count++; return nil }))
	if count != 1 {
		t.Fatal("snapshot enumeration changed")
	}
	must(t, tx.Close())
	must(t, tx.Close())
	if file, err := tx.Journal(); !errors.Is(err, appstorefile.ErrUnavailable) {
		if file != nil {
			file.Close()
		}
		t.Fatal("closed transaction remained usable")
	}
	fresh, err := other.Lock()
	must(t, err)
	must(t, fresh.Close())
}
func idBytes(value byte) []byte { valueID := id(value); return valueID[:] }

func TestNativeRecordBoundsCancellationAndAnonymousSpool(t *testing.T) {
	_, directory := fixture(t)
	tx, err := directory.Lock()
	must(t, err)
	defer tx.Close()
	if file, err := tx.CreateCandidate([16]byte{}); !errors.Is(err, appstorefile.ErrInvalid) {
		if file != nil {
			file.Close()
		}
		t.Fatal("zero candidate identity accepted")
	}
	for _, name := range []string{"../escape", "00000000000000000000000000000000.bin", "ABCDEF00000000000000000000000000.bin", "stream:secret"} {
		if file, err := tx.OpenNamed("candidates", name); !errors.Is(err, appstorefile.ErrInvalid) {
			if file != nil {
				file.Close()
			}
			t.Fatal("noncanonical record name accepted")
		}
	}
	candidate(t, tx, id(4), []byte("synthetic ciphertext"))
	file, err := tx.OpenCandidate(id(4))
	must(t, err)
	defer file.Close()
	if _, err := appstorefile.Hash(context.Background(), file, 1); !errors.Is(err, appstorefile.ErrInvalid) {
		t.Fatal("hash exceeded bound")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := appstorefile.Hash(ctx, file, 4096); !errors.Is(err, context.Canceled) {
		t.Fatal("hash ignored cancellation")
	}
	if err := tx.Retain(ctx, id(4), id(5), file, sha256.Sum256([]byte("synthetic ciphertext")), 4096); !errors.Is(err, context.Canceled) {
		t.Fatal("recovery ignored cancellation")
	}
	if _, err := tx.OpenRecovery(id(4), id(5)); !errors.Is(err, appstorefile.ErrMissing) {
		t.Fatal("cancelled recovery published a file")
	}
	spool, err := tx.Temporary()
	must(t, err)
	defer spool.Close()
	before, err := appstorefile.StatTemporary(spool)
	must(t, err)
	if before.Size != 0 {
		t.Fatal("spool was not empty before use")
	}
	_, err = spool.Write([]byte("synthetic anonymous ciphertext"))
	must(t, err)
	must(t, spool.Sync())
	after, err := appstorefile.StatTemporary(spool)
	must(t, err)
	if after.Dev != before.Dev || after.Ino != before.Ino || after.Size != 30 {
		t.Fatal("spool identity or ciphertext changed")
	}
	if _, err := appstorefile.Stat(spool); !errors.Is(err, appstorefile.ErrInvalid) {
		t.Fatal("anonymous spool accepted as named record")
	}
}
