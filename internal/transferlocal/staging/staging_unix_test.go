//go:build !windows

package staging_test

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

func TestStagingPrivatePermissionsUnix(t *testing.T) {
	_, dir := testRoot(t)
	staging, err := NewStaging("dest", dir, false)
	if err != nil {
		t.Fatalf("NewStaging: %v", err)
	}
	info, err := os.Lstat(staging.Path())
	if err != nil {
		t.Fatalf("Lstat(staging): %v", err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Fatalf("staging perm = %o, want 700", got)
	}
	payload, err := staging.CreatePayload()
	if err != nil {
		t.Fatalf("CreatePayload: %v", err)
	}
	payloadPath := filepath.Join(staging.Path(), "payload")
	if _, err := payload.Write([]byte("data")); err != nil {
		t.Fatalf("payload write: %v", err)
	}
	if err := payload.Close(); err != nil {
		t.Fatalf("payload close: %v", err)
	}
	pinfo, err := os.Lstat(payloadPath)
	if err != nil {
		t.Fatalf("Lstat(payload): %v", err)
	}
	if got := pinfo.Mode().Perm(); got != 0600 {
		t.Fatalf("payload perm = %o, want 600", got)
	}
	if err := staging.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
}

func TestPublishHardLinkUnix(t *testing.T) {
	_, dir := testRoot(t)
	staging, err := NewStaging("out.txt", dir, false)
	if err != nil {
		t.Fatalf("NewStaging: %v", err)
	}
	payload, err := staging.CreatePayload()
	if err != nil {
		t.Fatalf("CreatePayload: %v", err)
	}
	if _, err := payload.Write([]byte("payload bytes")); err != nil {
		t.Fatalf("payload write: %v", err)
	}
	payload.Close()
	payloadInfo, err := os.Lstat(filepath.Join(staging.Path(), "payload"))
	if err != nil {
		t.Fatalf("Lstat(payload): %v", err)
	}
	if err := staging.Publish(KindFile); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	destInfo, err := os.Lstat(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatalf("Lstat(dest): %v", err)
	}
	if !os.SameFile(payloadInfo, destInfo) {
		t.Fatal("destination is not the same inode as the payload; hard-link publication missing")
	}
	requireNoPath(t, staging.Path())
}

func TestExtractPermissionNormalizationUnix(t *testing.T) {
	_, dir := testRoot(t)
	staging, err := NewStaging("tree", dir, false)
	if err != nil {
		t.Fatalf("NewStaging: %v", err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	addDir := func(name string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
			t.Fatalf("WriteHeader(%s): %v", name, err)
		}
	}
	addFile := func(name string, mode int64, content string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(content))}); err != nil {
			t.Fatalf("WriteHeader(%s): %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("Write(%s): %v", name, err)
		}
	}
	addDir("d")
	addFile("d/plain.txt", 0644, "plain")
	addFile("d/run.sh", 0755, "#!/bin/sh\n")
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if _, err := ExtractTar(bytes.NewReader(buf.Bytes()), staging, nil, transfercore.DefaultLimits()); err != nil {
		t.Fatalf("ExtractTar: %v", err)
	}
	checkPerm := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("Lstat(%s): %v", path, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("perm of %s = %o, want %o", path, got, want)
		}
	}
	checkPerm(filepath.Join(staging.Path(), "d"), 0755)
	checkPerm(filepath.Join(staging.Path(), "d", "plain.txt"), 0644)
	checkPerm(filepath.Join(staging.Path(), "d", "run.sh"), 0755)
	if err := staging.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
}
