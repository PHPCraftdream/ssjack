//go:build linux

package recoveryintegration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
	"github.com/PHPCraftdream/ssjack/internal/recoveryjournal"
)

func TestDiskTamperingPoisonsJournal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "j")
	j, e := recoveryjournal.Initialize(root, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	intent := recovery.Intent{Binding: recovery.Binding{
		Stage: recovery.Reservation, Invocation: "tamper", Resource: "resource", Transaction: "tx",
		Expected: recovery.State{Resource: "resource"},
		Next:     recovery.State{Resource: "resource", Generation: 1, Transaction: "tx", Hash: recovery.Hash{1}},
	}, Phase: recovery.Prepared}
	if e = j.PutIntent(context.Background(), intent); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "journal.json")
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	b[len(b)/2] ^= 1
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = j.LoadIntent(context.Background(), "tamper"); !errors.Is(e, recoveryjournal.ErrUnavailable) {
		t.Fatal(e)
	}
}
