package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func TestAppstoreSetupRejectsMissingOrUnsafeDirectoryBeforePrompt(t *testing.T) {
	if !appstoreentry.Supported() {
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
	if !appstoreentry.Supported() {
		t.Skip("protected store unavailable on this platform")
	}
	dir := protectedStoreTestDirectory(t)
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
	if !appstoreentry.Supported() {
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
	dir := protectedStoreTestDirectory(t)
	code, err := run(context.Background(), []string{"appstore", "put", dir})
	if code == 0 || !errors.Is(err, errAppstore) {
		t.Fatalf("missing installation: %d %v", code, err)
	}
}

func protectedStoreTestDirectory(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store")
	root, err := ownerfs.MakeRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
