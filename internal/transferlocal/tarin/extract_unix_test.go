//go:build !windows

package tarin_test

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

func tarOneEntry(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(content))}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

func TestExtractThroughPreCreatedFileSymlinkUnix(t *testing.T) {
	_, dir := testRoot(t)
	target := filepath.Join(dir, "elsewhere-target")
	writeFile(t, target, []byte("original"))

	staging, err := NewStaging("out", dir, false)
	if err != nil {
		t.Fatalf("NewStaging: %v", err)
	}
	link := filepath.Join(staging.Path(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	defer os.Remove(link)
	_, err = ExtractTar(bytes.NewReader(tarOneEntry(t, "link", "overwritten")), staging, nil, transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("ReadFile(target): %v", readErr)
	}
	if string(data) != "original" {
		t.Fatalf("target was modified: %q", data)
	}
	if err := staging.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
}

func TestExtractThroughPreCreatedDirSymlinkUnix(t *testing.T) {
	_, dir := testRoot(t)
	target := filepath.Join(dir, "elsewhere-dir")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	staging, err := NewStaging("out", dir, false)
	if err != nil {
		t.Fatalf("NewStaging: %v", err)
	}
	link := filepath.Join(staging.Path(), "d")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	defer os.Remove(link)
	_, err = ExtractTar(bytes.NewReader(tarOneEntry(t, "d/inner.txt", "inside")), staging, nil, transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	entries, readErr := os.ReadDir(target)
	if readErr != nil {
		t.Fatalf("ReadDir(target): %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink target dir was written into: %d entries", len(entries))
	}
	if err := staging.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
}

func TestPublishOntoSymlinkDestinationRefusedUnix(t *testing.T) {
	_, dir := testRoot(t)
	victim := filepath.Join(dir, "victim.txt")
	writeFile(t, victim, []byte("keep"))
	dest := filepath.Join(dir, "dest")
	if err := os.Symlink(victim, dest); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	defer os.Remove(dest)

	staging, err := NewStaging("dest", dir, true)
	if err != nil {
		t.Fatalf("NewStaging: %v", err)
	}
	payload, err := staging.CreatePayload()
	if err != nil {
		t.Fatalf("CreatePayload: %v", err)
	}
	payload.Write([]byte("new"))
	payload.Close()
	publishErr := staging.Publish(KindFile)
	requireClass(t, publishErr, transfercore.ClassRefusedPath, dir)
	data, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatalf("ReadFile(victim): %v", readErr)
	}
	if string(data) != "keep" {
		t.Fatalf("victim content changed: %q", data)
	}
	info, statErr := os.Lstat(dest)
	if statErr != nil {
		t.Fatalf("Lstat(dest): %v", statErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("destination is no longer a symlink")
	}
	if err := staging.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
}

func TestPublishDirOntoSymlinkDestinationRefusedUnix(t *testing.T) {
	_, dir := testRoot(t)
	target := filepath.Join(dir, "dir-target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	dest := filepath.Join(dir, "destdir")
	if err := os.Symlink(target, dest); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	defer os.Remove(dest)
	staging, err := NewStaging("destdir", dir, true)
	if err != nil {
		t.Fatalf("NewStaging: %v", err)
	}
	publishErr := staging.Publish(KindDir)
	requireClass(t, publishErr, transfercore.ClassRefusedPath, dir)
	info, statErr := os.Lstat(dest)
	if statErr != nil {
		t.Fatalf("Lstat(dest): %v", statErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("destination is no longer a symlink")
	}
	if err := staging.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
}
