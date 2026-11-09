package ownerpublication

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNativePublicationPathRefusesAnEmptyName(t *testing.T) {
	if _, err := widePath(""); err == nil {
		t.Fatal("empty publication path became the working directory")
	}
}

func TestNativeFileFlushRepairsReadOnlyDirectoryHandleFailure(t *testing.T) {
	root := t.TempDir()
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	directoryError := parent.Sync()
	parent.Close()
	if !errors.Is(directoryError, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("fixture did not exercise the read-only directory flush failure")
	}
	path := filepath.Join(root, "database")
	value := []byte("synthetic encrypted publication")
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Sync(path); err != nil {
		t.Fatal("native write-through file handle could not flush the publication")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("native flush replaced the encrypted file")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(value) {
		t.Fatal("native flush changed encrypted bytes")
	}
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)
	if err := Sync(path); err == nil {
		t.Fatal("native flush hid a writable-handle refusal")
	}
	t.Log("Native encrypted publication accepted after read-only directory flush refusal.")
}
