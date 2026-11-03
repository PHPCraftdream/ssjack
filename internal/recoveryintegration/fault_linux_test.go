//go:build linux

package recoveryintegration

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
	"github.com/PHPCraftdream/ssjack/internal/recoveryjournal"
)

type hookedAnchor struct {
	base     *anchor
	afterCAS func()
}

func (h *hookedAnchor) Read(ctx context.Context, r string) (recovery.State, error) {
	return h.base.Read(ctx, r)
}
func (h *hookedAnchor) CompareAndSwap(ctx context.Context, old, next recovery.State, tx string) error {
	err := h.base.CompareAndSwap(ctx, old, next, tx)
	if h.afterCAS != nil {
		h.afterCAS()
	}
	return err
}

func TestPendingArtifactDetectedBeforeAnchorIO(t *testing.T) {
	j, root, a, b := setup(t)
	if err := os.WriteFile(filepath.Join(root, "journal.json.pending"), []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	m := recovery.Machine{Anchor: a, Journal: j}
	if err := m.Recover(context.Background(), b); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("Recover=%v", err)
	}
	if a.reads != 0 || a.swaps != 0 {
		t.Fatalf("anchor accessed: %+v", a)
	}
	raw, err := os.ReadFile(filepath.Join(root, "journal.json"))
	if err != nil || !bytes.Contains(raw, []byte(`"records":[]`)) {
		t.Fatalf("persisted journal=%s err=%v", raw, err)
	}
	if err = j.PutIntent(context.Background(), recovery.Intent{Binding: b, Phase: recovery.Prepared}); !errors.Is(err, recoveryjournal.ErrUnavailable) {
		t.Fatalf("admission after artifact=%v", err)
	}
	if err = m.Recover(context.Background(), b); !errors.Is(err, recovery.ErrUnavailable) || a.reads != 0 || a.swaps != 0 {
		t.Fatalf("repeat=%v anchor=%+v", err, a)
	}
}

func TestNewArtifactAfterCASPreservesPreparedEvidence(t *testing.T) {
	j, root, a, b := setup(t)
	h := &hookedAnchor{base: a, afterCAS: func() {
		if err := os.WriteFile(filepath.Join(root, "journal.json.new"), []byte("interrupted"), 0600); err != nil {
			t.Error(err)
		}
	}}
	m := recovery.Machine{Anchor: h, Journal: j}
	if err := m.Recover(context.Background(), b); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("Recover=%v", err)
	}
	if a.swaps != 1 || a.state != b.Next || !a.preparedOnDisk {
		t.Fatalf("anchor=%+v", a)
	}
	raw, err := os.ReadFile(filepath.Join(root, "journal.json"))
	if err != nil || !bytes.Contains(raw, []byte(`"Phase":1`)) || !bytes.Contains(raw, []byte(b.Transaction)) {
		t.Fatalf("prepared evidence=%s err=%v", raw, err)
	}
	if err = m.Recover(context.Background(), b); !errors.Is(err, recovery.ErrUnavailable) || a.swaps != 1 {
		t.Fatalf("repeat=%v anchor=%+v", err, a)
	}
}

func TestExpiredDeadlineStopsBeforeJournalMutation(t *testing.T) {
	j, _, a, b := setup(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := (recovery.Machine{Anchor: a, Journal: j}).Recover(ctx, b); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("Recover=%v", err)
	}
	if a.reads != 0 || a.swaps != 0 {
		t.Fatalf("expired request reached anchor: %+v", a)
	}
	if _, err := j.LoadIntent(context.Background(), b.Invocation); !errors.Is(err, recovery.ErrNotFound) {
		t.Fatalf("intent after expiry: %v", err)
	}
}

func TestCancellationBeforeCommitKeepsPreparedEvidence(t *testing.T) {
	j, root, a, b := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &hookedAnchor{base: a, afterCAS: cancel}
	if err := (recovery.Machine{Anchor: h, Journal: j}).Recover(ctx, b); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("Recover=%v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "journal.json"))
	if err != nil || !bytes.Contains(raw, []byte(`"Phase":1`)) || !bytes.Contains(raw, []byte(b.Transaction)) {
		t.Fatalf("prepared evidence=%s err=%v", raw, err)
	}
	got, err := j.LoadIntent(context.Background(), b.Invocation)
	if err != nil || got.Phase != recovery.Prepared {
		t.Fatalf("intent=%+v err=%v", got, err)
	}
	if a.swaps != 1 {
		t.Fatalf("CAS repeated: %d", a.swaps)
	}
}
