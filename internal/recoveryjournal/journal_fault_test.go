//go:build linux

package recoveryjournal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PHPCraftdream/ssjack/internal/recovery"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestBoundedLockContentionWhileSyncBlocked(t *testing.T) {
	j, e := Initialize(filepath.Join(t.TempDir(), "j"), 25*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	old := j.io.syncDir
	var once sync.Once
	j.io.syncDir = func(p string) error { once.Do(func() { close(entered); <-release }); return old(p) }
	done := make(chan error, 1)
	go func() { done <- j.PutIntent(context.Background(), prepared("blocked", "blocked-res")) }()
	<-entered
	start := time.Now()
	_, e = j.LoadIntent(context.Background(), "none")
	elapsed := time.Since(start)
	close(release)
	if !errors.Is(e, ErrUnavailable) || elapsed < 15*time.Millisecond || elapsed > time.Second {
		t.Fatalf("contention: %v %v", e, elapsed)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func TestLivePendingAndNewArtifactsPoisonJournal(t *testing.T) {
	for _, suffix := range []string{".pending", ".new"} {
		t.Run(suffix, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "j")
			j, err := Initialize(root, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(j.path()+suffix, []byte("interrupted"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = j.LoadIntent(context.Background(), "missing"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("live artifact not detected: %v", err)
			}
		})
	}
}
func TestInitializeParentSyncFailure(t *testing.T) {
	io := systemIO()
	io.syncDir = func(string) error { return errors.New("parent sync") }
	if _, e := initialize(filepath.Join(t.TempDir(), "j"), time.Second, io); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("initialize: %v", e)
	}
}
func TestDiskFaultsPoisonJournal(t *testing.T) {
	renamed := false
	faults := []struct {
		name      string
		set       func(*diskIO, string)
		published bool
	}{
		{"marker-create", func(io *diskIO, root string) {
			old := io.create
			io.create = func(p string) (*os.File, error) {
				if filepath.Ext(p) == ".pending" {
					return nil, errors.New("marker create")
				}
				return old(p)
			}
		}, false},
		{"new-create", func(io *diskIO, root string) {
			old := io.create
			io.create = func(p string) (*os.File, error) {
				if filepath.Ext(p) == ".new" {
					return nil, errors.New("new create")
				}
				return old(p)
			}
		}, false},
		{"marker-write", func(io *diskIO, root string) {
			old := io.write
			io.write = func(f *os.File, b []byte) error {
				if f.Name() == root+"/journal.json.pending" {
					_, _ = f.Write(b[:len(b)/2])
					return errors.New("marker write")
				}
				return old(f, b)
			}
		}, false},
		{"marker-sync", func(io *diskIO, root string) {
			old := io.sync
			io.sync = func(f *os.File) error {
				if filepath.Ext(f.Name()) == ".pending" {
					return errors.New("marker sync")
				}
				return old(f)
			}
		}, false},
		{"marker-close", func(io *diskIO, root string) {
			old := io.close
			io.close = func(f *os.File) error {
				e := old(f)
				if filepath.Ext(f.Name()) == ".pending" {
					return errors.New("marker close")
				}
				return e
			}
		}, false},
		{"marker-dir-sync", func(io *diskIO, root string) {
			old := io.syncDir
			io.syncDir = func(p string) error {
				if p == root {
					return errors.New("marker dir sync")
				}
				return old(p)
			}
		}, false},
		{"new-partial-write", func(io *diskIO, root string) {
			old := io.write
			io.write = func(f *os.File, b []byte) error {
				if filepath.Ext(f.Name()) == ".new" {
					n := len(b) / 2
					_, _ = f.Write(b[:n])
					return errors.New("partial new write")
				}
				return old(f, b)
			}
		}, false},
		{"new-sync", func(io *diskIO, root string) {
			old := io.sync
			io.sync = func(f *os.File) error {
				if filepath.Ext(f.Name()) == ".new" {
					return errors.New("new sync")
				}
				return old(f)
			}
		}, false},
		{"new-close", func(io *diskIO, root string) {
			old := io.close
			io.close = func(f *os.File) error {
				e := old(f)
				if filepath.Ext(f.Name()) == ".new" {
					return errors.New("new close")
				}
				return e
			}
		}, false},
		{"rename", func(io *diskIO, root string) {
			old := io.rename
			io.rename = func(a, b string) error {
				if filepath.Ext(a) == ".new" {
					return errors.New("rename")
				}
				return old(a, b)
			}
		}, false},
		{"post-rename-sync", func(io *diskIO, root string) {
			old := io.syncDir
			n := 0
			io.syncDir = func(p string) error {
				n++
				if p == root && n == 2 {
					return errors.New("post rename sync")
				}
				return old(p)
			}
		}, true},
		{"rename-succeeds-error", func(io *diskIO, root string) {
			io.rename = func(a, b string) error {
				if filepath.Ext(a) == ".new" {
					if err := os.Rename(a, b); err != nil {
						return err
					}
					renamed = true
					return errors.New("ambiguous rename")
				}
				return os.Rename(a, b)
			}
		}, true},
		{"remove", func(io *diskIO, root string) {
			old := io.remove
			io.remove = func(p string) error {
				if filepath.Ext(p) == ".pending" {
					return errors.New("remove")
				}
				return old(p)
			}
		}, true},
		{"final-sync", func(io *diskIO, root string) {
			old := io.syncDir
			n := 0
			io.syncDir = func(p string) error {
				n++
				if p == root && n == 3 {
					return errors.New("final sync")
				}
				return old(p)
			}
		}, true},
	}
	for _, tc := range faults {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "j")
			j, err := Initialize(root, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(j.path())
			if err != nil {
				t.Fatal(err)
			}
			renamed = false
			tc.set(&j.io, root)
			i := prepared("fault", "fault-res")
			err = (recovery.Machine{Anchor: faultAnchor{}, Journal: j}).Recover(context.Background(), i.Binding)
			if tc.name == "rename-succeeds-error" && !renamed {
				t.Fatal("rename hook not reached")
			}
			if !errors.Is(err, recovery.ErrUnavailable) || !j.poisoned {
				t.Fatalf("fault returned %v, poisoned=%v", err, j.poisoned)
			}
			if _, err = j.LoadIntent(context.Background(), "fault"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("journal not poisoned: %v", err)
			}
			after, err := os.ReadFile(j.path())
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "rename-succeeds-error" {
				var doc document
				if err = json.Unmarshal(after, &doc); err != nil {
					t.Fatal(err)
				}
				if len(doc.Records) != 1 || doc.Records[0].Intent != i {
					t.Fatalf("persisted intent: %+v", doc.Records)
				}
			}
			changed := string(after) != string(before)
			if changed != tc.published {
				t.Fatalf("disk changed=%v want=%v", changed, tc.published)
			}
			if tc.published {
				if _, err = Initialize(root, time.Second); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("existing directory refused: %v", err)
				}
			}
		})
	}
}

type faultAnchor struct{}

func (faultAnchor) Read(context.Context, string) (recovery.State, error) { panic("anchor touched") }
func (faultAnchor) CompareAndSwap(context.Context, recovery.State, recovery.State, string) error {
	panic("anchor touched")
}
func TestCapacityAndIdempotence(t *testing.T) {
	j, e := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	for n := 0; n < maxEntries; n++ {
		i := recovery.Intent{Binding: validBinding(fmt.Sprintf("i%d", n), fmt.Sprintf("r%d", n), fmt.Sprintf("t%d", n)), Phase: recovery.Prepared}
		if e = j.PutIntent(context.Background(), i); e != nil {
			t.Fatal(e)
		}
	}
	i := recovery.Intent{Binding: validBinding("i0", "r0", "t0"), Phase: recovery.Prepared}
	if e = j.PutIntent(context.Background(), i); e != nil {
		t.Fatal(e)
	}
	if e = j.PutIntent(context.Background(), recovery.Intent{Binding: validBinding("overflow", "overflow-res", "overflow-tx"), Phase: recovery.Prepared}); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
}
