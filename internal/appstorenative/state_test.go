package appstorenative

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func TestNativeOperationLeaseExcludesCloseAndConcurrentMutation(t *testing.T) {
	root, err := ownerfs.MakeRoot(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.File()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := Open(file, [16]byte{1})
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	release, err := tx.Begin()
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		other, err := tx.Begin()
		if other != nil {
			other()
		}
		result <- err
	}()
	if err := <-result; err != nil {
		release()
		t.Fatal("shared read operation could not acquire a lease")
	}
	mutation, err := tx.mutation()
	if err != nil {
		release()
		t.Fatal(err)
	}
	candidate, mutationErr := tx.CreateCandidate([16]byte{2})
	if candidate != nil {
		candidate.Close()
	}
	mutation()
	if !errors.Is(mutationErr, ownerfs.ErrBusy) {
		release()
		t.Fatal("concurrent mutation bypassed its exclusive gate")
	}
	if err := tx.Close(); !errors.Is(err, ownerfs.ErrBusy) {
		release()
		t.Fatal("close invalidated live operation")
	}
	if err := directory.Close(); !errors.Is(err, ownerfs.ErrBusy) {
		release()
		t.Fatal("directory closed during transaction")
	}
	release()
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	if release, err := tx.Begin(); !errors.Is(err, ownerfs.ErrUnavailable) {
		if release != nil {
			release()
		}
		t.Fatal("stale operation acquired lease")
	}
	fresh, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRecordCanonicalNames(t *testing.T) {
	for _, value := range []struct {
		kind, name string
		valid      bool
	}{
		{"snapshots", "00000000000000000000000000000001.bin", true},
		{"recovery", "00000000000000000000000000000001-00000000000000000000000000000002.bin", true},
		{"candidates", "00000000000000000000000000000000.bin", false},
		{"snapshots", "0000000000000000000000000000000A.bin", false},
		{"recovery", "00000000000000000000000000000001-00000000000000000000000000000000.bin", false},
		{"intents", "../00000000000000000000000000000001.bin", false},
		{"unknown", "00000000000000000000000000000001.bin", false},
	} {
		if canonical(value.kind, value.name) != value.valid {
			t.Fatal("canonical record name contract changed")
		}
	}
}
