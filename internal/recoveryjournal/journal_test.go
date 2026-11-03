//go:build linux

package recoveryjournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
)

func TestBindingValidationAndPersistedRoundTrip(t *testing.T) {
	b := validBinding("check-inv", "check-res", "check-tx")
	if !recovery.ValidBinding(b) {
		t.Fatal("valid binding rejected")
	}
	invalid := b
	invalid.Next.Generation = 3
	if recovery.ValidBinding(invalid) {
		t.Fatal("invalid binding accepted")
	}
	j, err := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	intent := recovery.Intent{Binding: b, Phase: recovery.Prepared}
	if err = j.PutIntent(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	got, err := j.LoadIntent(context.Background(), b.Invocation)
	if err != nil || got != intent {
		t.Fatalf("round trip: %v %v", got, err)
	}
	doc := document{Version: 1, Records: []record{{Intent: recovery.Intent{Binding: invalid, Phase: recovery.Prepared}}}}
	doc.Digest = digest(doc)
	j.last = doc
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(j.path(), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = j.LoadIntent(context.Background(), b.Invocation); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid persisted binding: %v", err)
	}
}

func TestQuarantineConflictPreservesAndFencesBothStoredBindings(t *testing.T) {
	j, e := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	a, b := validBinding("both-a", "both-res-a", "tx-a"), validBinding("both-b", "both-res-b", "tx-b")
	for _, x := range []recovery.Binding{a, b} {
		if e = j.PutIntent(context.Background(), recovery.Intent{Binding: x, Phase: recovery.Prepared}); e != nil {
			t.Fatal(e)
		}
	}
	if e = j.QuarantineConflict(context.Background(), a, b); e != nil {
		t.Fatal(e)
	}
	for _, x := range []recovery.Binding{a, b} {
		got, err := j.LoadIntent(context.Background(), x.Invocation)
		if !errors.Is(err, recovery.ErrQuarantined) {
			t.Fatalf("%+v %v", got, err)
		}
		stored, err := j.load()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, record := range stored.Records {
			if record.Intent.Binding == x && record.Intent.Phase == recovery.Quarantined {
				found = true
			}
		}
		if !found {
			t.Fatalf("quarantined evidence missing for %s", x.Invocation)
		}
		if e = j.PutIntent(context.Background(), prepared("new-"+x.Invocation, x.Resource)); !errors.Is(e, recovery.ErrQuarantined) {
			t.Fatal(e)
		}
	}
}
func TestMalformedAndOversizedDiskDenied(t *testing.T) {
	for _, name := range []string{"duplicate-json-key"} {
		t.Run(name, func(t *testing.T) {
			j, e := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			base := document{Version: 1, Records: []record{{Intent: recovery.Intent{Binding: validBinding("base", "base-res", "tx"), Phase: recovery.Prepared}}}}
			base.Digest = digest(base)
			j.last = base
			b, e := json.Marshal(base)
			if e != nil {
				t.Fatal(e)
			}
			b = []byte(strings.Replace(string(b), `"version":1`, `"version":1,"version":1`, 1))
			if e = os.WriteFile(j.path(), b, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e = j.LoadIntent(context.Background(), "x"); !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
			if string(mustJSON(j.last)) != string(mustJSON(base)) {
				t.Fatal("invalid disk document replaced cached last")
			}
		})
	}
}

// This gate models a caller-owned global fence, not a production admission mechanism.
type publicationGate struct {
	closed bool
	admits int
}

func (g *publicationGate) recover(ctx context.Context, m recovery.Machine, b recovery.Binding) error {
	if g.closed {
		return recovery.ErrUnavailable
	}
	g.admits++
	err := m.Recover(ctx, b)
	if errors.Is(err, recovery.ErrUnavailable) {
		g.closed = true
	}
	return err
}

type observedJournal struct {
	*Journal
	loads, conflicts int
	conflictErr      error
}

func (j *observedJournal) LoadIntent(ctx context.Context, id string) (recovery.Intent, error) {
	j.loads++
	return j.Journal.LoadIntent(ctx, id)
}

func (j *observedJournal) QuarantineConflict(ctx context.Context, a, b recovery.Binding) error {
	j.conflicts++
	j.conflictErr = j.Journal.QuarantineConflict(ctx, a, b)
	return j.conflictErr
}

func TestConflictPostRenameFailureClosesCallerGate(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	j, err := Initialize(root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	stored := validBinding("shared-invocation", "stored-resource", "stored-tx")
	requested := validBinding(stored.Invocation, "requested-resource", "requested-tx")
	other := validBinding("other-invocation", "other-resource", "other-tx")
	if err := j.PutIntent(ctx, recovery.Intent{Binding: stored, Phase: recovery.Prepared}); err != nil {
		t.Fatal(err)
	}

	// Fail the directory sync only after the real rename has succeeded.
	rename, syncDir := j.io.rename, j.io.syncDir
	renamed, syncFailed := false, false
	j.io.rename = func(from, to string) error {
		err := rename(from, to)
		if err == nil && from == j.newPath() && to == j.path() {
			renamed = true
		}
		return err
	}
	j.io.syncDir = func(path string) error {
		if path == root && renamed {
			syncFailed = true
			return errors.New("injected post-rename directory sync failure")
		}
		return syncDir(path)
	}
	observed := &observedJournal{Journal: j}
	gate := &publicationGate{}
	machine := recovery.Machine{Anchor: faultAnchor{}, Journal: observed}
	if err := gate.recover(ctx, machine, requested); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("conflict recovery: %v", err)
	}
	if !renamed || !syncFailed || !errors.Is(observed.conflictErr, ErrUnavailable) || !j.poisoned {
		t.Fatalf("publication: renamed=%v syncFailed=%v quarantine=%v poisoned=%v", renamed, syncFailed, observed.conflictErr, j.poisoned)
	}
	if !gate.closed || gate.admits != 1 || observed.loads != 1 || observed.conflicts != 1 {
		t.Fatalf("conflict: gate=%+v loads=%d conflicts=%d", gate, observed.loads, observed.conflicts)
	}
	marker, err := os.ReadFile(j.pendingPath())
	if err != nil || string(marker) != "pending" {
		t.Fatalf("publication marker=%q err=%v", marker, err)
	}
	if _, err := os.Lstat(j.newPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("renamed new file remains: %v", err)
	}
	raw, err := os.ReadFile(j.path())
	if err != nil {
		t.Fatal(err)
	}
	var evidence document
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	if !validDoc(evidence) || evidence.Digest != digest(evidence) || len(evidence.Records) != 1 {
		t.Fatalf("invalid published evidence: %+v", evidence)
	}
	r := evidence.Records[0]
	if r.Intent.Binding != stored || r.Intent.Phase != recovery.Quarantined || len(r.Blocked) != 2 || r.Blocked[0] != stored || r.Blocked[1] != requested {
		t.Fatalf("published conflict evidence: %+v", r)
	}
	if _, err := j.LoadIntent(ctx, stored.Invocation); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("journal did not fail closed: %v", err)
	}
	if err := gate.recover(ctx, machine, other); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("unrelated binding admitted: %v", err)
	}
	if !gate.closed || gate.admits != 1 || observed.loads != 1 || observed.conflicts != 1 {
		t.Fatalf("unrelated request reached journal: gate=%+v loads=%d conflicts=%d", gate, observed.loads, observed.conflicts)
	}
}

func TestConflictPublicationIOFailureClosesCallerGate(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	j, err := Initialize(root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	stored := validBinding("shared-invocation", "stored-resource", "stored-tx")
	requested := validBinding(stored.Invocation, "requested-resource", "requested-tx")
	other := validBinding("other-invocation", "other-resource", "other-tx")
	if err := j.PutIntent(ctx, recovery.Intent{Binding: stored, Phase: recovery.Prepared}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(j.path())
	if err != nil {
		t.Fatal(err)
	}

	// Install the obstruction only when publication creates .new, after load
	// and after the journal itself has created and synced its pending marker.
	create := j.io.create
	var createErr error
	var obstructionErr error
	attempts := 0
	j.io.create = func(path string) (*os.File, error) {
		if path == j.newPath() {
			attempts++
			obstructionErr = os.Mkdir(path, 0700)
			if obstructionErr != nil {
				return nil, obstructionErr
			}
			f, err := create(path)
			createErr = err
			return f, err
		}
		return create(path)
	}
	observed := &observedJournal{Journal: j}
	gate := &publicationGate{}
	machine := recovery.Machine{Anchor: faultAnchor{}, Journal: observed}
	if err := gate.recover(ctx, machine, requested); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("conflict recovery: %v", err)
	}
	if obstructionErr != nil || attempts != 1 || !errors.Is(createErr, os.ErrExist) || !errors.Is(observed.conflictErr, ErrUnavailable) {
		t.Fatalf("publication: attempts=%d obstruction=%v create=%v quarantine=%v", attempts, obstructionErr, createErr, observed.conflictErr)
	}
	if !gate.closed || gate.admits != 1 || observed.loads != 1 || observed.conflicts != 1 {
		t.Fatalf("conflict: gate=%+v loads=%d conflicts=%d", gate, observed.loads, observed.conflicts)
	}
	marker, err := os.ReadFile(j.pendingPath())
	if err != nil || string(marker) != "pending" {
		t.Fatalf("publication marker=%q err=%v", marker, err)
	}
	after, err := os.ReadFile(j.path())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("original evidence changed: err=%v", err)
	}
	if _, err := j.LoadIntent(ctx, stored.Invocation); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("journal did not fail closed: %v", err)
	}
	if err := gate.recover(ctx, machine, other); !errors.Is(err, recovery.ErrUnavailable) {
		t.Fatalf("unrelated binding admitted: %v", err)
	}
	if !gate.closed || gate.admits != 1 || observed.loads != 1 || observed.conflicts != 1 {
		t.Fatalf("unrelated request reached journal: gate=%+v loads=%d conflicts=%d", gate, observed.loads, observed.conflicts)
	}
}
