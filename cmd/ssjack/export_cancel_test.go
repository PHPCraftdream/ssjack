package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAlreadyCancelledExportDoesNotPromptOrWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported-key")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := exportVaultKey(ctx, path, []byte("unused"), []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled export reached prompting or file publication: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("cancelled export created a file")
	}
	called := false
	if err := publishKeyExport(ctx, path, nil, nil, func(_, _ []byte) ([]byte, error) {
		called = true
		return nil, nil
	}); !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled export started cryptographic work")
	}
}

func TestExportCancelledDuringEncryptionDoesNotPublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported-key")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := publishKeyExport(ctx, path, []byte("in-memory private fixture"), []byte("export secret"), func(_, _ []byte) ([]byte, error) {
		cancel()
		return []byte("encrypted fixture"), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("export cancellation was lost: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("private export was published after cancellation")
	}
}

func TestExportEncryptionFailureDoesNotPublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported-key")
	failure := errors.New("encryption failed")
	err := publishKeyExport(context.Background(), path, nil, nil, func(_, _ []byte) ([]byte, error) { return nil, failure })
	if !errors.Is(err, failure) {
		t.Fatal("encryption error was lost")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed export created a file")
	}
}
