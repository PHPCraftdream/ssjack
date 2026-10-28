// No build constraint: Linux-only cases skip on unsupported platforms.
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

func prepared(i, r string) recovery.Intent {
	return recovery.Intent{Binding: validBinding(i, r, "tx"), Phase: recovery.Prepared}
}
func validBinding(i, r, tx string) recovery.Binding {
	return recovery.Binding{Stage: recovery.Reservation, Invocation: i, Resource: r, Transaction: tx, Expected: recovery.State{Resource: r}, Next: recovery.State{Resource: r, Generation: 1, Transaction: tx, Hash: recovery.Hash{1}}}
}

func TestBindingValidationMatrix(t *testing.T) {
	base := validBinding("matrix-inv", "matrix-res", "matrix-tx")
	valid := base
	valid.Invocation = string(make([]byte, 0))
	valid.Invocation = strings.Repeat("a", 128)
	if !recovery.ValidBinding(valid) {
		t.Fatal("printable ASCII length 128 rejected")
	}
	tooLong := valid
	tooLong.Invocation += "a"
	invalidUTF8 := base
	invalidUTF8.Resource = string([]byte{0xff})
	invalidUTF8.Expected.Resource, invalidUTF8.Next.Resource = invalidUTF8.Resource, invalidUTF8.Resource
	for name, b := range map[string]recovery.Binding{"129-byte identifier": tooLong, "raw invalid UTF-8": invalidUTF8} {
		t.Run(name, func(t *testing.T) {
			if recovery.ValidBinding(b) {
				t.Fatal("invalid binding accepted")
			}
		})
	}
	cases := []struct {
		name string
		edit func(*recovery.Binding)
	}{
		{"stage", func(b *recovery.Binding) { b.Stage = 255 }},
		{"genesis generation", func(b *recovery.Binding) { b.Expected.Generation = 0; b.Expected.Transaction = "prior" }},
		{"genesis transaction", func(b *recovery.Binding) {
			b.Expected.Generation = 1
			b.Expected.Transaction = ""
			b.Next.Generation = 2
		}},
		{"transaction", func(b *recovery.Binding) { b.Next.Transaction = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := base
			tc.edit(&b)
			if recovery.ValidBinding(b) {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}

func TestValidNonGenesisDiskRoundTrip(t *testing.T) {
	if !supported() {
		t.Skip("disk journal unavailable")
	}
	b := validBinding("roundtrip-inv", "roundtrip-res", "roundtrip-tx")
	b.Stage = recovery.InvocationStage
	b.Expected = recovery.State{Resource: b.Resource, Generation: 7, Hash: recovery.Hash{2}, Transaction: "prior-tx"}
	b.Next = recovery.State{Resource: b.Resource, Generation: 8, Hash: recovery.Hash{1}, Transaction: b.Transaction}
	in := recovery.Intent{Binding: b, Phase: recovery.Prepared}
	j, err := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.PutIntent(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	got, err := j.LoadIntent(context.Background(), b.Invocation)
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Fatalf("round trip = %+v, want %+v", got, in)
	}
}

func TestInitializeUnavailableOnUnsupportedPlatform(t *testing.T) {
	if supported() {
		t.Skip("platform supports journal")
	}
	if _, err := Initialize(filepath.Join(t.TempDir(), "j"), time.Second); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Initialize error = %v, want ErrUnavailable", err)
	}
}

func TestQuarantinePublicationFaults(t *testing.T) {
	if !supported() {
		t.Skip("Linux journal unavailable")
	}
	for _, phase := range []string{"marker", "new"} {
		t.Run(phase, func(t *testing.T) {
			j, err := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			a, b := validBinding("qa", "qra", "qta"), validBinding("qb", "qrb", "qtb")
			for _, x := range []recovery.Binding{a, b} {
				if err = j.PutIntent(context.Background(), recovery.Intent{Binding: x, Phase: recovery.Prepared}); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(j.path())
			if err != nil {
				t.Fatal(err)
			}
			if phase == "marker" {
				old := j.io.write
				j.io.write = func(f *os.File, b []byte) error {
					if filepath.Ext(f.Name()) == ".pending" {
						return errors.New("marker")
					}
					return old(f, b)
				}
			} else {
				old := j.io.sync
				j.io.sync = func(f *os.File) error {
					if filepath.Ext(f.Name()) == ".new" {
						return errors.New("new sync")
					}
					return old(f)
				}
			}
			if err = j.QuarantineConflict(context.Background(), a, b); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("quarantine: %v", err)
			}
			after, err := os.ReadFile(j.path())
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatalf("pre-rename %s fault changed journal", phase)
			}
			if _, err = j.LoadIntent(context.Background(), a.Invocation); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("poison: %v", err)
			}
		})
	}
}

func TestQuarantineConflictPostRenameFaultsPreserveEvidence(t *testing.T) {
	if !supported() {
		t.Skip("Linux journal unavailable")
	}
	for _, fault := range []string{"remove", "final-sync", "post-rename-sync"} {
		t.Run(fault, func(t *testing.T) {
			j, err := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			a, b := validBinding("post-a", "post-res-a", "post-tx-a"), validBinding("post-b", "post-res-b", "post-tx-b")
			for _, x := range []recovery.Binding{a, b} {
				if err = j.PutIntent(context.Background(), recovery.Intent{Binding: x, Phase: recovery.Prepared}); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "remove" {
				old := j.io.remove
				j.io.remove = func(path string) error {
					if path == j.pendingPath() {
						return errors.New("marker remove")
					}
					return old(path)
				}
			} else {
				old := j.io.syncDir
				n := 0
				j.io.syncDir = func(path string) error {
					if path == j.root {
						n++
						if fault == "post-rename-sync" && n == 2 {
							return errors.New("post-rename sync")
						}
						if fault == "final-sync" && n == 3 {
							return errors.New("final sync")
						}
					}
					return old(path)
				}
			}
			if err = j.QuarantineConflict(context.Background(), a, b); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("quarantine: %v", err)
			}
			if !j.poisoned {
				t.Fatal("journal not poisoned")
			}
			raw, err := os.ReadFile(j.path())
			if err != nil {
				t.Fatal(err)
			}
			var doc document
			if err = json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Records) != 2 {
				t.Fatalf("records=%d", len(doc.Records))
			}
			for _, want := range []recovery.Binding{a, b} {
				found := false
				for _, rec := range doc.Records {
					if rec.Intent.Binding == want && rec.Intent.Phase == recovery.Quarantined {
						found = true
					}
				}
				if !found {
					t.Fatalf("original binding/phase not preserved: %+v", want)
				}
			}
		})
	}
}
func TestQuarantineConflictDiskEvidenceAndInterlocks(t *testing.T) {
	if !supported() {
		t.Skip("Linux journal unavailable")
	}
	j, err := Initialize(filepath.Join(t.TempDir(), "j"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	a, b := validBinding("qa", "qra", "qta"), validBinding("qb", "qrb", "qtb")
	for _, x := range []recovery.Binding{a, b} {
		if err = j.PutIntent(context.Background(), recovery.Intent{Binding: x, Phase: recovery.Prepared}); err != nil {
			t.Fatal(err)
		}
	}
	if err = j.QuarantineConflict(context.Background(), a, b); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(j.path())
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err = json.Unmarshal(disk, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Records) != 2 {
		t.Fatalf("records=%d", len(doc.Records))
	}
	for _, x := range []recovery.Binding{a, b} {
		found := false
		for _, r := range doc.Records {
			if r.Intent.Binding == x && r.Intent.Phase == recovery.Quarantined {
				found = true
			}
		}
		if !found {
			t.Fatalf("evidence missing: %s", x.Invocation)
		}
		if _, err = j.LoadIntent(context.Background(), x.Invocation); !errors.Is(err, recovery.ErrQuarantined) {
			t.Fatalf("load: %v", err)
		}
		if err = j.PutIntent(context.Background(), prepared("new-"+x.Invocation, x.Resource)); !errors.Is(err, recovery.ErrQuarantined) {
			t.Fatalf("fence: %v", err)
		}
	}
}

func TestBoundedReadAcceptsSizeBeforeCanonicalValidation(t *testing.T) {
	base := document{Version: 1, Records: []record{}}
	base.Digest = digest(base)
	valid, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	input := append(valid, bytes.Repeat([]byte(" "), maxJournal-len(valid))...)
	got, err := readBounded(bytes.NewReader(input))
	if err != nil || len(got) != maxJournal {
		t.Fatalf("max-size read: len=%d err=%v", len(got), err)
	}
	if _, err = readBounded(bytes.NewReader(append(input, ' '))); !errors.Is(err, errJournalTooLarge) {
		t.Fatalf("max+1 error: %v", err)
	}
}
