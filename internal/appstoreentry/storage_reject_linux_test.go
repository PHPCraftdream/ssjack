//go:build linux

package appstoreentry

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryReplacementInvalidatesStore(t *testing.T) {
	parent := t.TempDir()
	p := filepath.Join(parent, "store")
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	moved := filepath.Join(parent, "moved")
	if err := os.Rename(p, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Install([]byte("ciphertext")); err == nil {
		t.Fatal("operation accepted replaced directory path")
	}
}

func TestNilClosedAndBounds(t *testing.T) {
	var nilStore *Store
	if nilStore.Close() != nil {
		t.Fatal("nil Close failed")
	}
	if _, err := nilStore.Root(); err == nil {
		t.Fatal("nil Root succeeded")
	}
	if nilStore.Install([]byte("x")) == nil {
		t.Fatal("nil Install succeeded")
	}
	if _, _, err := nilStore.Load(); err == nil {
		t.Fatal("nil Load succeeded")
	}
	if nilStore.VerifyUnchanged([32]byte{}) == nil {
		t.Fatal("nil Verify succeeded")
	}
	p := privateDir(t)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Root(); err == nil {
		t.Fatal("closed Root succeeded")
	}
	if s.Install([]byte("x")) == nil {
		t.Fatal("closed Install succeeded")
	}
	if _, _, err := s.Load(); err == nil {
		t.Fatal("closed Load succeeded")
	}
	if s.VerifyUnchanged([32]byte{}) == nil {
		t.Fatal("closed Verify succeeded")
	}
	if errors.Is(s.Install(nil), nil) {
		t.Fatal("empty install succeeded")
	}
	live, err := Open(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if live.Install(nil) == nil || live.Install(make([]byte, maxBinding+1)) == nil {
		t.Fatal("invalid binding size accepted")
	}
}
