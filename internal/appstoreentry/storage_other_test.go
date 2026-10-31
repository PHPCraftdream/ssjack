//go:build !linux

package appstoreentry

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedStorageFailsClosedWithoutFilesystemMutation(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "missing", "store")
	if Supported() {
		t.Fatal("unsupported platform reported support")
	}
	store, err := Open(path)
	if store != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open = (%v, %v), want (nil, ErrUnsupported)", store, err)
	}
	if _, err := os.Lstat(filepath.Join(parent, "missing")); !os.IsNotExist(err) {
		t.Fatalf("Open mutated filesystem: %v", err)
	}
	if err := (*Store)(nil).Close(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Close error = %v", err)
	}
	if _, err := (*Store)(nil).Root(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Root error = %v", err)
	}
	if err := (*Store)(nil).Install([]byte("ciphertext")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Install error = %v", err)
	}
	if _, _, err := (*Store)(nil).Load(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Load error = %v", err)
	}
	if err := (*Store)(nil).VerifyUnchanged([32]byte{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("VerifyUnchanged error = %v", err)
	}
}
