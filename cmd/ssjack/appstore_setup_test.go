package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
)

func TestAppstoreSetupRejectsMissingOrUnsafeDirectoryBeforePrompt(t *testing.T) {
	if runtime.GOOS != "linux" {
		if appstoreentry.Supported() {
			t.Fatal("expected appstore unsupported outside Linux")
		}
		calls := 0
		old := appstoreReadInput
		appstoreReadInput = func(string, bool) ([]byte, error) { calls++; return []byte("secret"), nil }
		defer func() { appstoreReadInput = old }()
		if code, err := run(context.Background(), []string{"appstore", "setup", t.TempDir()}); code == 0 || !errors.Is(err, appstoreentry.ErrUnsupported) || calls != 0 {
			t.Fatalf("unsupported setup = %d, %v; prompts=%d", code, err, calls)
		}
		return
	}
	calls := 0
	old := appstoreReadInput
	appstoreReadInput = func(string, bool) ([]byte, error) { calls++; return []byte("secret"), nil }
	defer func() { appstoreReadInput = old }()
	parent := t.TempDir()
	missing := filepath.Join(parent, "missing")
	if code, err := run(context.Background(), []string{"appstore", "setup", missing}); code == 0 || err == nil {
		t.Fatalf("missing directory accepted: %d %v", code, err)
	}
	missingEntries, readErr := os.ReadDir(parent)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(missingEntries) != 0 || calls != 0 {
		t.Fatalf("missing directory prompted/created files: entries=%v prompts=%d", missingEntries, calls)
	}
	// A writable-by-group directory must be rejected before any secret prompt.
	unsafe := filepath.Join(parent, "unsafe")
	if err := os.Mkdir(unsafe, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0770); err != nil {
		t.Fatal(err)
	}
	if code, err := run(context.Background(), []string{"appstore", "setup", unsafe}); code == 0 || err == nil {
		t.Fatalf("unsafe directory accepted: %d %v", code, err)
	}
	entries, readErr := os.ReadDir(unsafe)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 || calls != 0 {
		t.Fatalf("unsafe directory prompted/created files: entries=%v prompts=%d", entries, calls)
	}
}

func TestAppstoreSetupCancellationStopsBeforeInstallation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific directory safety")
	}
	dir := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, err := runAppstoreSetup(ctx, dir)
	if code == 0 || err == nil {
		t.Fatalf("cancelled setup accepted: %d %v", code, err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("cancelled setup created files: %v", entries)
	}
}

func TestAppstorePutMissingInstallationFailsWithoutSecret(t *testing.T) {
	if runtime.GOOS != "linux" {
		if appstoreentry.Supported() {
			t.Fatal("expected appstore unsupported outside Linux")
		}
		calls := 0
		old := appstoreReadInput
		appstoreReadInput = func(string, bool) ([]byte, error) { calls++; return []byte("secret"), nil }
		defer func() { appstoreReadInput = old }()
		code, err := run(context.Background(), []string{"appstore", "put", filepath.Join(t.TempDir(), "missing")})
		if code == 0 || !errors.Is(err, appstoreentry.ErrUnsupported) || calls != 0 {
			t.Fatalf("put = %d, %v; prompts=%d", code, err, calls)
		}
		return
	}
	dir := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	code, err := run(context.Background(), []string{"appstore", "put", dir})
	if code == 0 || !errors.Is(err, errAppstore) {
		t.Fatalf("missing installation: %d %v", code, err)
	}
}
