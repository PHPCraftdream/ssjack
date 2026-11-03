//go:build linux

package appstoreanchorledger

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func TestSyncUncertaintyFencesUntilVerifiedRestart(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		b, dir, _ := fixture(t, 8)
		read, create, reserve, _ := operations(t)
		writer := scope(t, 5, appstoreanchorcore.Writer)
		execute(t, b, create, writer, appstoreanchorreply.Committed)
		calls := 0
		b.state.syncFile = func(f *os.File) error {
			calls++
			if calls == failAt {
				return errors.New("private sync detail")
			}
			return f.Sync()
		}
		if result, err := b.Execute(reserve, writer); err != ErrUncertain || result.Valid() {
			t.Fatal("uncertain publication acknowledged")
		}
		if result, err := b.Execute(read, writer); err != ErrUncertain || result.Valid() {
			t.Fatal("fenced backend served stale current state")
		}
		if len(b.state.records) != 1 {
			t.Fatal("memory published before durability")
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		recovered, err := New(dir, id(1), 8)
		if err != nil {
			t.Fatal(err)
		}
		execute(t, recovered, reserve, writer, appstoreanchorreply.Committed)
		if err := recovered.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPartialRecordIsNeverTruncatedOrServed(t *testing.T) {
	b, dir, path := fixture(t, 8)
	read, create, _, _ := operations(t)
	writer := scope(t, 5, appstoreanchorcore.Writer)
	b.state.write = func(p []byte) (int, error) {
		n, _ := b.state.log.Write(p[:100])
		return n, errors.New("private write detail")
	}
	if result, err := b.Execute(create, writer); err != ErrUncertain || result.Valid() {
		t.Fatal("partial record accepted")
	}
	if _, err := b.Execute(read, writer); err != ErrUncertain {
		t.Fatal("fence missing")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(path, "anchor.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if next, err := New(dir, id(1), 8); next != nil || err != ErrInvalid {
		t.Fatal("partial tail silently recovered", err)
	}
	after, err := os.ReadFile(filepath.Join(path, "anchor.bin"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("partial record altered")
	}
}

func TestRecoveryRejectsCorruptionAndCapacityMismatch(t *testing.T) {
	for _, kind := range []string{"header", "index", "hash", "reply", "forged-result", "short", "trailing", "duplicate", "capacity"} {
		t.Run(kind, func(t *testing.T) {
			b, dir, path := fixture(t, 4)
			_, create, _, _ := operations(t)
			execute(t, b, create, scope(t, 5, appstoreanchorcore.Writer), appstoreanchorreply.Committed)
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(path, "anchor.bin")
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			capacity := 4
			switch kind {
			case "header":
				data[8] ^= 1
			case "index":
				data[headerSize+8] ^= 1
			case "hash":
				data[len(data)-1] ^= 1
			case "reply":
				data[headerSize+356+9] ^= 1
			case "forged-result":
				data[headerSize+356+9] ^= 1
				previous := sha256.Sum256(append([]byte("SSAPP-ANCHOR-LEDGER-GENESIS-v1"), data[:headerSize]...))
				store := id(1)
				message := append([]byte("SSAPP-ANCHOR-LEDGER-RECORD-v1"), store[:]...)
				message = append(message, previous[:]...)
				message = append(message, data[headerSize:headerSize+644]...)
				rehashed := sha256.Sum256(message)
				copy(data[headerSize+644:], rehashed[:])
			case "short":
				data = data[:len(data)-1]
			case "trailing":
				data = append(data, 0)
			case "duplicate":
				data = append(data, append([]byte(nil), data[headerSize:]...)...)
			case "capacity":
				capacity = 3
			}
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			if next, err := New(dir, id(1), capacity); next != nil || err != ErrInvalid {
				t.Fatalf("corruption accepted: %v", err)
			}
			after, err := os.ReadFile(name)
			if err != nil || !bytes.Equal(data, after) {
				t.Fatal("recovery modified evidence")
			}
		})
	}
}

func TestLifetimeLockClosedAliasesAndInputBounds(t *testing.T) {
	b, dir, path := fixture(t, 4)
	_, create, _, _ := operations(t)
	writer := scope(t, 5, appstoreanchorcore.Writer)
	if other, err := New(dir, id(1), 4); err != ErrBusy || other != nil {
		t.Fatal("second writer admitted")
	}
	for _, capacity := range []int{0, MaxRecords + 1} {
		if other, err := New(dir, id(1), capacity); err != ErrInvalid || other != nil {
			t.Fatal("unbounded capacity admitted")
		}
	}
	if other, err := New(nil, id(1), 1); err != ErrInvalid || other != nil {
		t.Fatal("nil directory")
	}
	if other, err := New(dir, [16]byte{}, 1); err != ErrInvalid || other != nil {
		t.Fatal("zero store")
	}
	b.state.mu.Lock()
	_, err := b.Execute(create, writer)
	b.state.mu.Unlock()
	if err != ErrBusy {
		t.Fatal("in-process contention admitted")
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Execute(create, writer); err != ErrUnavailable {
		t.Fatal("unsafe root accepted")
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Execute(create, writer); err != ErrUncertain {
		t.Fatal("fence revoked by chmod")
	}
	alias := *b
	if err := alias.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Execute(create, writer); err != ErrClosed {
		t.Fatal("alias close not shared")
	}
	var empty Backend
	for _, value := range []*Backend{nil, &empty} {
		if err := value.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := value.Execute(create, writer); err != ErrClosed {
			t.Fatal("zero backend accepted")
		}
	}
}

func TestUnsafeLedgerNamesAndModesAreRejected(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "mode"} {
		t.Run(kind, func(t *testing.T) {
			b, dir, path := fixture(t, 2)
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(path, "anchor.bin")
			switch kind {
			case "symlink":
				if err := os.Rename(name, name+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("anchor.bin.saved", name); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(name, name+".saved"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(name, 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(name, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if next, err := New(dir, id(1), 2); next != nil || err == nil {
				t.Fatal("unsafe ledger accepted")
			}
		})
	}
}

func TestConcurrentExpectedStateCASSucceedsAtMostOnce(t *testing.T) {
	b, _, _ := fixture(t, 8)
	read, create, reserve, _ := operations(t)
	writer := scope(t, 5, appstoreanchorcore.Writer)
	execute(t, b, create, writer, appstoreanchorreply.Committed)
	genesis, _ := appstoreanchorstate.Genesis(id(1))
	entry, _ := appstorejournal.NewEntry(0, id(6), id(7))
	planned, err := appstoreanchorrequest.PlanReservation(genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	alternate := request(t, planned)
	start := make(chan struct{})
	results := make(chan struct {
		r   appstoreanchorcore.Result
		err error
	}, 2)
	for _, r := range []appstoreanchorcore.Request{reserve, alternate} {
		go func(r appstoreanchorcore.Request) {
			<-start
			result, err := b.Execute(r, writer)
			results <- struct {
				r   appstoreanchorcore.Result
				err error
			}{result, err}
		}(r)
	}
	close(start)
	successes := 0
	for i := 0; i < 2; i++ {
		got := <-results
		if got.err == nil && got.r.Outcome() == appstoreanchorreply.Committed {
			successes++
		} else if got.err != ErrBusy && (got.err != nil || got.r.Outcome() != appstoreanchorreply.Conflict) {
			t.Fatal("unexpected concurrent result", got.err)
		}
	}
	if successes != 1 {
		t.Fatal("expected-state CAS did not serialize")
	}
	execute(t, b, read, writer, appstoreanchorreply.ReadState)
}
