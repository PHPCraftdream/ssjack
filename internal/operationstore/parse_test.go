package operationstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParseStateStrict(t *testing.T) {
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	stateWith := func(key string) string {
		return fmt.Sprintf(`{"version":1,"records":[{"key":%s,"canonical_target":"t","canonical_resource":"r","plan_digest":"%s","quarantined":false}],"quarantined":false}`, key, digest)
	}
	good := stateWith(`"k"`)
	if _, err := parseState([]byte(good)); err != nil {
		t.Fatalf("valid state: %v", err)
	}
	for name, key := range map[string]string{
		"escaped ASCII":     `"\u0061"`,
		"escaped backslash": `"\\"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseState([]byte(stateWith(key))); err != nil {
				t.Fatalf("valid escaped string: %v", err)
			}
		})
	}
	cases := map[string]string{
		"duplicate top-level field": `{"records":[],"version":1,"version":1,"quarantined":false}`,
		"non-ASCII identity":        stateWith(`"é"`),
		"high surrogate":            stateWith(`"\ud800"`),
		"low surrogate":             stateWith(`"\udc00"`),
		"invalid UTF-8":             stateWith("\"" + string([]byte{0xff}) + "\""),
		"null records":              `{"version":1,"records":null,"quarantined":false}`,
		"missing field":             `{"version":1,"records":[{"key":"k","canonical_target":"t","canonical_resource":"r","plan_digest":"` + digest + `"}],"quarantined":false}`,
		"duplicate record field":    `{"version":1,"records":[{"key":"k","key":"other","canonical_target":"t","canonical_resource":"r","plan_digest":"` + digest + `","quarantined":false}],"quarantined":false}`,
		"duplicate record key":      `{"version":1,"records":[{"key":"k","canonical_target":"t","canonical_resource":"r","plan_digest":"` + digest + `","quarantined":false},{"key":"k","canonical_target":"t2","canonical_resource":"r2","plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","quarantined":false}],"quarantined":false}`,
		"unknown record field":      `{"version":1,"records":[{"key":"k","canonical_target":"t","canonical_resource":"r","plan_digest":"` + digest + `","quarantined":false,"future":1}],"quarantined":false}`,
		"inconsistent quarantine":   `{"version":1,"quarantined":true,"records":[{"key":"k","canonical_target":"t","canonical_resource":"r","plan_digest":"` + digest + `","quarantined":false}]}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseState([]byte(input)); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("accepted invalid state: %v", err)
			}
		})
	}
	q := `{"version":1,"quarantined":true,"records":[{"key":"k","canonical_target":"t","canonical_resource":"r","plan_digest":"` + digest + `","quarantined":true}]}`
	if _, err := parseState([]byte(q)); !errors.Is(err, ErrConflict) {
		t.Fatalf("quarantine: %v", err)
	}
}

func TestIdentitiesArePrintableASCII(t *testing.T) {
	for _, v := range []string{"ok", "é", "\nlead", "nul\x00"} {
		if valid(v) != (v == "ok") {
			t.Errorf("valid(%q) = %v", v, valid(v))
		}
	}
}

func TestParseRejectsDuplicatePairs(t *testing.T) {
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	record := func(key string) string {
		return fmt.Sprintf(`{"key":%q,"canonical_target":"t","canonical_resource":"r","plan_digest":"%s","quarantined":false}`, key, digest)
	}
	input := `{"version":1,"records":[` + record("k1") + `,` + record("k2") + `],"quarantined":false}`
	if _, err := parseState([]byte(input)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("duplicate pair: %v", err)
	}
}

func TestInitializePublicationTrace(t *testing.T) {
	if !publicationSupported() {
		t.Skip("durable publication is supported only on Linux")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	base := systemPublicationIO()
	var trace []string
	p := publicationIO{
		createFile: func(path string, flags int, mode os.FileMode) (*os.File, error) {
			trace = append(trace, "create:"+filepath.Base(path))
			return base.createFile(path, flags, mode)
		},
		writeFile: func(f *os.File, b []byte) error {
			trace = append(trace, "write:"+filepath.Base(f.Name()))
			return base.writeFile(f, b)
		},
		syncFile: func(f *os.File) error {
			trace = append(trace, "sync-file:"+filepath.Base(f.Name()))
			return base.syncFile(f)
		},
		closeFile: func(f *os.File) error {
			trace = append(trace, "close:"+filepath.Base(f.Name()))
			return base.closeFile(f)
		},
		rename: func(from, to string) error {
			trace = append(trace, "rename:"+filepath.Base(from)+":"+filepath.Base(to))
			return base.rename(from, to)
		},
		syncDir: func(path string) error {
			name := filepath.Base(path)
			if path == parent {
				name = "parent"
			}
			trace = append(trace, "sync-dir:"+name)
			return base.syncDir(path)
		},
		remove: func(path string) error {
			trace = append(trace, "remove:"+filepath.Base(path))
			return base.remove(path)
		},
	}
	if _, err := initialize(root, time.Second, p); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"create:.pending", "write:.pending", "sync-file:.pending", "close:.pending", "sync-dir:state",
		"create:state.json", "write:state.json", "sync-file:state.json", "close:state.json",
		"sync-dir:state", "sync-dir:parent", "remove:.pending", "sync-dir:state",
	}
	if !reflect.DeepEqual(trace, want) {
		t.Fatalf("initialize syscall trace\n got: %#v\nwant: %#v", trace, want)
	}
}

func TestPublicationTraceAndNormalLookup(t *testing.T) {
	if !publicationSupported() {
		t.Skip("durable publication is supported only on Linux")
	}
	root := filepath.Join(t.TempDir(), "state")
	s, err := Initialize(root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	base := systemPublicationIO()
	var trace []string
	p := publicationIO{
		createFile: func(path string, flags int, mode os.FileMode) (*os.File, error) {
			trace = append(trace, "create:"+filepath.Base(path))
			return base.createFile(path, flags, mode)
		},
		writeFile: func(f *os.File, b []byte) error {
			trace = append(trace, "write:"+filepath.Base(f.Name()))
			return base.writeFile(f, b)
		},
		syncFile: func(f *os.File) error {
			trace = append(trace, "sync-file:"+filepath.Base(f.Name()))
			return base.syncFile(f)
		},
		closeFile: func(f *os.File) error {
			trace = append(trace, "close:"+filepath.Base(f.Name()))
			return base.closeFile(f)
		},
		rename: func(from, to string) error {
			trace = append(trace, "rename:"+filepath.Base(from)+":"+filepath.Base(to))
			return base.rename(from, to)
		},
		syncDir: func(path string) error {
			trace = append(trace, "sync-dir:"+filepath.Base(path))
			return base.syncDir(path)
		},
		remove: func(path string) error {
			trace = append(trace, "remove:"+filepath.Base(path))
			return base.remove(path)
		},
	}
	s.io = p
	wantRecord := sample("trace-baseline")
	if got, err := s.Reserve(context.Background(), wantRecord); err != nil || got != wantRecord {
		t.Fatalf("reserve: %#v, %v", got, err)
	}
	wantTrace := []string{
		"create:.pending", "write:.pending", "sync-file:.pending", "close:.pending", "sync-dir:state",
		"create:state.json.new", "write:state.json.new", "sync-file:state.json.new", "close:state.json.new",
		"rename:state.json.new:state.json", "sync-dir:state", "sync-dir:state", "remove:.pending", "sync-dir:state",
	}
	if !reflect.DeepEqual(trace, wantTrace) {
		t.Fatalf("publication syscall trace\n got: %#v\nwant: %#v", trace, wantTrace)
	}
	if got, err := s.Lookup(context.Background(), wantRecord.Key); err != nil || got != wantRecord {
		t.Fatalf("normal lookup: %#v, %v", got, err)
	}
}

func TestInitializationFailuresFailClosed(t *testing.T) {
	if !publicationSupported() {
		t.Skip("durable publication is supported only on Linux")
	}
	stages := []string{"parent sync", "marker write", "marker sync", "marker close", "state write", "state sync", "state close", "marker removal", "marker removal after remove", "final marker removal sync"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "isolated-state")
			p := systemPublicationIO()
			triggered, removed, calls := false, false, 0
			trigger := func() error { triggered = true; return errors.New("injected " + stage) }
			isMarker := func(f *os.File) bool { return filepath.Base(f.Name()) == ".pending" }
			if stage == "marker write" || stage == "state write" {
				p.writeFile = func(f *os.File, b []byte) error {
					if isMarker(f) == (stage == "marker write") {
						return trigger()
					}
					return systemPublicationIO().writeFile(f, b)
				}
			}
			if stage == "marker sync" || stage == "state sync" {
				p.syncFile = func(f *os.File) error {
					if isMarker(f) == (stage == "marker sync") {
						return trigger()
					}
					return f.Sync()
				}
			}
			if stage == "marker close" || stage == "state close" {
				p.closeFile = func(f *os.File) error {
					name := f.Name()
					err := f.Close()
					if (filepath.Base(name) == ".pending") == (stage == "marker close") {
						return trigger()
					}
					return err
				}
			}
			if stage == "marker removal" || stage == "marker removal after remove" {
				p.remove = func(path string) error {
					if stage == "marker removal" {
						return trigger()
					}
					if err := os.Remove(path); err != nil {
						return err
					}
					removed = true
					return trigger()
				}
			}
			p.syncDir = func(path string) error {
				calls++
				if stage == "parent sync" && path == parent || stage == "final marker removal sync" && path == root && calls == 4 {
					return trigger()
				}
				return syncDirectory(path)
			}
			s, err := initialize(root, time.Second, p)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("initialize: %v", err)
			}
			if !triggered {
				t.Fatal("injected failure not reached")
			}
			if stage == "marker write" || stage == "marker sync" || stage == "marker close" || stage == "parent sync" || stage == "marker removal" {
				if _, err := os.Stat(filepath.Join(root, ".pending")); err != nil {
					t.Fatalf("pending marker not preserved: %v", err)
				}
			}
			poisonExpected := stage == "marker removal" || stage == "marker removal after remove" || stage == "final marker removal sync"
			if stage == "marker removal after remove" && !removed {
				t.Fatal("marker was not removed")
			}
			if poisonExpected {
				if s == nil || !s.poisoned {
					t.Fatal("store was not returned poisoned")
				}
				if _, err := s.Reserve(context.Background(), sample("after-init-failure")); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("poisoned reserve: %v", err)
				}
			}
			if _, err := Open(root, time.Second); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Open: %v", err)
			}
		})
	}
}
