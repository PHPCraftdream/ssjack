package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
)

// A blocked open of a writer-less FIFO would wedge the owner worker, so every
// refusal below must return promptly instead of waiting on the path.
func requireRefusedPromptly(t *testing.T, name, path string) {
	t.Helper()
	type result struct {
		opened *ownerarchive.Opened
		err    error
	}
	done := make(chan result, 1)
	go func() {
		opened, err := ownerarchive.ReadFile(context.Background(), path, nil)
		done <- result{opened, err}
	}()
	select {
	case got := <-done:
		if got.opened != nil || !errors.Is(got.err, ownerarchive.ErrArchive) {
			got.opened.Close()
			t.Fatalf("%s: archive path was not refused with ErrArchive", name)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: ReadFile blocked on a non-regular path", name)
	}
}

func TestOwnerArchiveReadFileRefusesNonRegularPathsWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.bin")
	content := []byte("synthetic, not a zip archive")
	if err := os.WriteFile(regular, content, 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("cannot create a FIFO here")
	}
	linkRegular, linkFIFO := filepath.Join(dir, "link-regular"), filepath.Join(dir, "link-fifo")
	if err := os.Symlink(regular, linkRegular); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, linkFIFO); err != nil {
		t.Fatal(err)
	}
	// Refuse a path replaced before opening; this does not simulate a raced open.
	raced, other := filepath.Join(dir, "raced.zip"), filepath.Join(dir, "other-pipe")
	if err := os.WriteFile(raced, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(other, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, raced); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"fifo": fifo, "symlink to regular": linkRegular, "symlink to fifo": linkFIFO, "replaced by fifo": raced, "non-zip regular": regular} {
		requireRefusedPromptly(t, name, path)
	}
	if after, err := os.ReadFile(regular); err != nil || !bytes.Equal(after, content) {
		t.Fatal("refused read changed the source file")
	}
}
