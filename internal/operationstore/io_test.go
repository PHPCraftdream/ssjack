package operationstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicationFailureHooksAreInjectable(t *testing.T) {
	want := errors.New("injected")
	p := publicationIO{writeFile: func(*os.File, []byte) error { return want }}
	s := &Store{io: p}
	if !errors.Is(s.publication().writeFile(nil, nil), want) {
		t.Fatal("write hook not used")
	}
}

func TestPublicationFailuresFailClosed(t *testing.T) {
	if !publicationSupported() {
		t.Skip("durable publication is supported only on Linux")
	}
	stages := []string{"marker create", "marker write", "marker sync", "marker close", "partial write", "file sync", "close", "rename", "directory sync before rename", "directory sync after rename", "final directory sync", "quarantine write", "quarantine sync"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			s, err := Initialize(root, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			baseline := sample("baseline")
			if got, err := s.Reserve(context.Background(), baseline); err != nil || got != baseline {
				t.Fatalf("healthy baseline reserve: %#v, %v", got, err)
			}
			if got, err := s.Lookup(context.Background(), baseline.Key); err != nil || got != baseline {
				t.Fatalf("healthy baseline lookup: %#v, %v", got, err)
			}
			before, err := os.ReadFile(s.statePath())
			if err != nil {
				t.Fatal(err)
			}

			want := errors.New("injected " + stage)
			p := systemPublicationIO()
			triggered := false
			fail := func() error {
				if !triggered {
					triggered = true
					return want
				}
				return nil
			}
			switch stage {
			case "marker create":
				p.createFile = func(path string, flags int, mode os.FileMode) (*os.File, error) {
					if path == filepath.Join(root, ".pending") {
						triggered = true
						return nil, want
					}
					return os.OpenFile(path, flags, mode)
				}
			case "marker write":
				p.writeFile = func(f *os.File, b []byte) error {
					if filepath.Base(f.Name()) == ".pending" {
						return fail()
					}
					return systemPublicationIO().writeFile(f, b)
				}
			case "marker sync":
				p.syncFile = func(f *os.File) error {
					if filepath.Base(f.Name()) == ".pending" {
						return fail()
					}
					return f.Sync()
				}
			case "marker close":
				p.closeFile = func(f *os.File) error {
					marker := filepath.Base(f.Name()) == ".pending"
					e := f.Close()
					if marker {
						if x := fail(); x != nil {
							return x
						}
					}
					return e
				}
			case "partial write":
				p.writeFile = func(f *os.File, b []byte) error {
					if filepath.Ext(f.Name()) == ".new" {
						if len(b) > 0 {
							_, _ = f.Write(b[:1])
						}
						return fail()
					}
					return systemPublicationIO().writeFile(f, b)
				}
			case "file sync":
				p.syncFile = func(f *os.File) error {
					if filepath.Ext(f.Name()) == ".new" {
						return fail()
					}
					return f.Sync()
				}
			case "close":
				p.closeFile = func(f *os.File) error {
					target := filepath.Ext(f.Name()) == ".new"
					e := f.Close()
					if target {
						if x := fail(); x != nil {
							return x
						}
					}
					return e
				}
			case "rename":
				p.rename = func(a, b string) error {
					if a == s.statePath()+".new" && b == s.statePath() {
						if e := fail(); e != nil {
							return e
						}
					}
					return os.Rename(a, b)
				}
			case "directory sync before rename":
				calls := 0
				p.syncDir = func(path string) error {
					calls++
					if calls == 1 {
						return fail()
					}
					return syncDirectory(path)
				}
			case "directory sync after rename":
				calls := 0
				p.syncDir = func(path string) error {
					calls++
					if calls == 2 {
						return fail()
					}
					return syncDirectory(path)
				}
			case "final directory sync":
				calls := 0
				p.syncDir = func(path string) error {
					calls++
					if calls == 4 {
						return fail()
					}
					return syncDirectory(path)
				}
			case "quarantine write", "quarantine sync":
				p.writeFile = func(f *os.File, b []byte) error {
					if filepath.Ext(f.Name()) == ".new" {
						if stage == "quarantine write" {
							return fail()
						}
					}
					return systemPublicationIO().writeFile(f, b)
				}
				if stage == "quarantine sync" {
					p.syncFile = func(f *os.File) error {
						if filepath.Ext(f.Name()) == ".new" {
							return fail()
						}
						return f.Sync()
					}
				}
			}
			s.io = p
			request := sample("new")
			if stage != "quarantine write" && stage != "quarantine sync" {
				request.CanonicalResource = "other"
			} else {
				request = sample("conflicting")
				request.CanonicalResource = baseline.CanonicalResource
			}
			_, err = s.Reserve(context.Background(), request)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("failure result: %v", err)
			}
			if !triggered {
				t.Fatal("injected filesystem failure was not reached")
			}
			if stage == "quarantine write" || stage == "quarantine sync" {
				if _, err := s.Lookup(context.Background(), baseline.Key); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("quarantine lookup: %v", err)
				}
			}
			if stage == "marker create" {
				// A failed O_EXCL create has no effect: no marker exists, so prior durable state remains readable.
				if _, statErr := os.Lstat(filepath.Join(root, ".pending")); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("marker unexpectedly exists: %v", statErr)
				}
				if got, lookupErr := s.Lookup(context.Background(), baseline.Key); lookupErr != nil || got != baseline {
					t.Fatalf("healthy lookup after pre-effect create failure: %#v, %v", got, lookupErr)
				}
			} else if got, lookupErr := s.Lookup(context.Background(), baseline.Key); !errors.Is(lookupErr, ErrUnavailable) {
				t.Fatalf("live key lookup: %#v, %v", got, lookupErr)
			}
			if _, err := Open(root, time.Second); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("reopen permitted: %v", err)
			}
			if stage == "final directory sync" {
				if _, err := s.Lookup(context.Background(), baseline.Key); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("poisoned instance lookup: %v", err)
				}
			}
			after, readErr := os.ReadFile(s.statePath())
			if readErr != nil {
				t.Fatal(readErr)
			}
			if stage != "directory sync after rename" && stage != "quarantine write" && stage != "quarantine sync" && !errors.Is(err, ErrUnavailable) {
				t.Fatal("unexpected result")
			}
			if stage == "marker create" || stage == "marker write" || stage == "marker sync" || stage == "marker close" || stage == "partial write" || stage == "file sync" || stage == "close" || stage == "rename" || stage == "directory sync before rename" {
				if !bytes.Equal(before, after) {
					t.Fatal("real baseline state changed")
				}
			}
		})
	}
}

func TestRemoveFailurePoisonsStore(t *testing.T) {
	if !publicationSupported() {
		t.Skip("durable publication is supported only on Linux")
	}
	root := filepath.Join(t.TempDir(), "state")
	s, err := Initialize(root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	baseline := sample("live")
	if _, err := s.Reserve(context.Background(), baseline); err != nil {
		t.Fatalf("baseline reserve: %v", err)
	}
	p := systemPublicationIO()
	p.remove = func(path string) error {
		if err := os.Remove(path); err != nil {
			return err
		}
		return errors.New("removed but failed")
	}
	s.io = p
	if _, err := s.Reserve(context.Background(), sample("next")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("reserve failure: %v", err)
	}
	if !s.poisoned {
		t.Fatal("store was not poisoned")
	}
	if _, err := s.Lookup(context.Background(), baseline.Key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("live key lookup: %v", err)
	}
	if _, err := Open(root, time.Second); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Open: %v", err)
	}
}
