package staging_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

func stageFile(t *testing.T, destRel, dir, content string, overwrite bool) *Staging {
	t.Helper()
	staging, err := NewStaging(destRel, dir, overwrite)
	if err != nil {
		t.Fatal(err)
	}
	file, err := staging.CreatePayload()
	if err != nil {
		t.Fatal(err)
	}
	_, werr := file.Write([]byte(content))
	serr := file.Sync()
	cerr := file.Close()
	if werr != nil || serr != nil || cerr != nil {
		t.Fatal("staging payload could not be written")
	}
	return staging
}

func stageDir(t *testing.T, destRel, dir string, files map[string]string, overwrite bool) *Staging {
	t.Helper()
	staging, err := NewStaging(destRel, dir, overwrite)
	if err != nil {
		t.Fatal(err)
	}
	for rel, content := range files {
		writeFile(t, filepath.Join(staging.Path(), filepath.FromSlash(rel)), []byte(content))
	}
	return staging
}

func TestPublishFileNoOverwrite(t *testing.T) {
	_, dir := testRoot(t)
	staging := stageFile(t, "dest.txt", dir, "payload-bytes", false)
	if err := staging.Publish(KindFile); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "dest.txt"))
	if err != nil || string(got) != "payload-bytes" {
		t.Fatalf("published bytes differ: %v", err)
	}
	requireNoPath(t, staging.Path())
	if _, err := NewStaging("dest.txt", dir, false); err == nil {
		t.Fatal("NewStaging accepted an existing destination")
	} else {
		requireClass(t, err, transfercore.ClassExists, dir)
	}
	late, err := NewStaging("late.txt", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "late.txt"), []byte("appeared"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := late.CreatePayload()
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	requireClass(t, late.Publish(KindFile), transfercore.ClassExists, dir, "appeared")
	if err := late.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishFileOverwrite(t *testing.T) {
	_, dir := testRoot(t)
	dest := filepath.Join(dir, "dest.txt")
	writeFile(t, dest, []byte("old-content"))
	if err := stageFile(t, "dest.txt", dir, "new-content", true).Publish(KindFile); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "new-content" {
		t.Fatalf("destination not replaced: %v", err)
	}
	if err := stageFile(t, "fresh.txt", dir, "fresh", true).Publish(KindFile); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "fresh.txt")); err != nil || string(got) != "fresh" {
		t.Fatalf("overwrite onto absent destination failed: %v", err)
	}
	writeFile(t, filepath.Join(dir, "adir", "inner.txt"), []byte("inner"))
	staging := stageFile(t, "adir", dir, "not-a-dir", true)
	requireClass(t, staging.Publish(KindFile), transfercore.ClassRefusedPath, dir)
	if err := staging.Abort(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "adir", "inner.txt")); err != nil || string(got) != "inner" {
		t.Fatal("directory destination was damaged")
	}
}

func TestPublishDirNoOverwrite(t *testing.T) {
	_, dir := testRoot(t)
	staging := stageDir(t, "dest", dir, map[string]string{"a.txt": "aaa", "sub/b.txt": "bbb"}, false)
	if err := staging.Publish(KindDir); err != nil {
		t.Fatal(err)
	}
	requireNoPath(t, staging.Path())
	if got, err := os.ReadFile(filepath.Join(dir, "dest", "sub", "b.txt")); err != nil || string(got) != "bbb" {
		t.Fatalf("published tree differs: %v", err)
	}
	if _, err := NewStaging("dest", dir, false); err == nil {
		t.Fatal("NewStaging accepted an existing destination")
	} else {
		requireClass(t, err, transfercore.ClassExists, dir)
	}
	late, err := NewStaging("late", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "late"), 0700); err != nil {
		t.Fatal(err)
	}
	requireClass(t, late.Publish(KindDir), transfercore.ClassExists, dir)
	if err := late.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishDirOverwrite(t *testing.T) {
	_, dir := testRoot(t)
	writeFile(t, filepath.Join(dir, "dest", "old.txt"), []byte("old"))
	staging := stageDir(t, "dest", dir, map[string]string{"new.txt": "new"}, true)
	if err := staging.Publish(KindDir); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "dest", "new.txt")); err != nil || string(got) != "new" {
		t.Fatalf("new tree missing: %v", err)
	}
	requireNoPath(t, filepath.Join(dir, "dest", "old.txt"))
	requireNoPath(t, staging.Path())
}

func TestPublishDirOverwriteFailureRestores(t *testing.T) {
	_, dir := testRoot(t)
	writeFile(t, filepath.Join(dir, "dest", "old.txt"), []byte("old"))
	staging, err := NewStaging("dest", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(staging.Path()); err != nil {
		t.Fatal(err)
	}
	requireClass(t, staging.Publish(KindDir), transfercore.ClassInternal, dir)
	if got, err := os.ReadFile(filepath.Join(dir, "dest", "old.txt")); err != nil || string(got) != "old" {
		t.Fatal("destination was not preserved")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".ssjack-transfer-") {
			t.Fatalf("staging leftover in parent: %s", entry.Name())
		}
	}
}

func TestNewStagingRefusals(t *testing.T) {
	_, dir := testRoot(t)
	for _, rel := range []string{"a\\b", "a:b", "x.", "/abs", "", "missing/x", ".git/x", "CON"} {
		if _, err := NewStaging(rel, dir, false); err == nil {
			t.Fatalf("destRel %q accepted", rel)
		} else {
			requireClass(t, err, transfercore.ClassRefusedPath, dir)
		}
	}
	writeFile(t, filepath.Join(dir, "taken"), []byte("taken"))
	if _, err := NewStaging("taken", dir, false); err == nil {
		t.Fatal("existing destination accepted")
	} else {
		requireClass(t, err, transfercore.ClassExists, dir)
	}
}

func TestStagingNamePattern(t *testing.T) {
	_, dir := testRoot(t)
	staging, err := NewStaging("dest", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(staging.Path())
	const prefix = ".ssjack-transfer-"
	if !strings.HasPrefix(base, prefix) {
		t.Fatalf("staging name: %q", base)
	}
	if suffix := base[len(prefix):]; len(suffix) != 12 {
		t.Fatalf("staging suffix length: %d", len(suffix))
	} else {
		for _, r := range suffix {
			if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
				t.Fatalf("staging suffix not lowercase hex: %q", suffix)
			}
		}
	}
	if err := staging.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestAbortRemovesOnlyStaging(t *testing.T) {
	_, dir := testRoot(t)
	staging, err := NewStaging("dest", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(dir, "sibling.txt")
	writeFile(t, sibling, []byte("keep"))
	if err := staging.Abort(); err != nil {
		t.Fatal(err)
	}
	requireNoPath(t, staging.Path())
	if got, err := os.ReadFile(sibling); err != nil || string(got) != "keep" {
		t.Fatal("sibling was removed by abort")
	}
	if err := staging.Abort(); err != nil {
		t.Fatalf("second abort: %v", err)
	}
}

func TestAbortAfterRemoval(t *testing.T) {
	_, dir := testRoot(t)
	staging, err := NewStaging("dest", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(staging.Path()); err != nil {
		t.Fatal(err)
	}
	if err := staging.Abort(); err != nil {
		t.Fatalf("abort after removal: %v", err)
	}
}

func TestAbortRefusesForeignSwap(t *testing.T) {
	_, dir := testRoot(t)
	staging, err := NewStaging("dest", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(staging.Path()); err != nil {
		t.Fatal(err)
	}
	writeFile(t, staging.Path(), []byte("foreign"))
	requireClass(t, staging.Abort(), transfercore.ClassInternal, dir, "foreign")
	if got, err := os.ReadFile(staging.Path()); err != nil || string(got) != "foreign" {
		t.Fatal("foreign content was damaged")
	}
}

func TestStagingLifecycleRefusals(t *testing.T) {
	_, dir := testRoot(t)
	aborted, err := NewStaging("a", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := aborted.Abort(); err != nil {
		t.Fatal(err)
	}
	_, err = aborted.CreatePayload()
	requireClass(t, err, transfercore.ClassInternal)
	archive := tarArchive(t, []tarEntry{regEntry("payload", 3)})
	_, err = ExtractTar(bytes.NewReader(archive), aborted, nil, transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassInternal)
	requireClass(t, aborted.Publish(KindFile), transfercore.ClassInternal)
	twice, err := NewStaging("b", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	file, err := twice.CreatePayload()
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = twice.CreatePayload()
	requireClass(t, err, transfercore.ClassInternal)
	if err := twice.Abort(); err != nil {
		t.Fatal(err)
	}
}
