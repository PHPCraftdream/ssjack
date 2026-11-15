package transferengine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestUploadDirOverEntriesRefusedBeforeRemote(t *testing.T) {
	fake := newFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxEntries = 3
	engine := testEngine(t, fake, limits)
	root := testRoot(t)
	for _, name := range []string{"a.txt", "b.txt", "c.txt", "d.txt"} {
		writeLocalFile(t, root, "src/"+name, []byte("x"))
	}

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	expectClass(t, err, transfercore.ClassLimit)
	expectNoResult(t, result)
	if n := fake.callCount("Probe"); n != 0 {
		t.Fatalf("Probe ran %d times before the entry refusal", n)
	}
	if n := fake.callCount("CreateStaging"); n != 0 {
		t.Fatalf("CreateStaging ran %d times before the entry refusal", n)
	}
}

func TestUploadDirOverBytesRefusedBeforeRemote(t *testing.T) {
	fake := newFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := testEngine(t, fake, limits)
	root := testRoot(t)
	writeLocalFile(t, root, "src/big.bin", binaryContent(4096))

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	expectClass(t, err, transfercore.ClassLimit)
	expectNoResult(t, result)
	if n := fake.callCount("Probe"); n != 0 {
		t.Fatalf("Probe ran %d times before the byte refusal", n)
	}
	if n := fake.callCount("CreateStaging"); n != 0 {
		t.Fatalf("CreateStaging ran %d times before the byte refusal", n)
	}
}

func TestUploadDirStreamOverLimit(t *testing.T) {
	fake := newFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 64
	engine := testEngine(t, fake, limits)
	root := testRoot(t)
	// The walk passes (40 bytes); the tar stream (512-byte header plus
	// padding) crosses the limit only while streaming.
	writeLocalFile(t, root, "src/mid.bin", binaryContent(40))

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	expectClass(t, err, transfercore.ClassLimit)
	expectNoResult(t, result)
	if fake.publishCount() != 0 {
		t.Fatal("over-limit upload published the destination")
	}
	if n := fake.callCount("VerifyTree"); n != 0 {
		t.Fatalf("VerifyTree ran %d times after a stream limit failure", n)
	}
	if n := fake.callCount("PublishDir"); n != 0 {
		t.Fatalf("PublishDir ran %d times after a stream limit failure", n)
	}
	if n := fake.callCount("CleanupStaging"); n != 1 {
		t.Fatalf("CleanupStaging ran %d times, want 1", n)
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

func TestDownloadDirOverEntriesRefusedBeforeStaging(t *testing.T) {
	fake := newFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxEntries = 1
	engine := testEngine(t, fake, limits)
	root := testRoot(t)
	fake.mkdir("/data/tree")
	fake.put("/data/tree/a.txt", []byte("alpha"))
	fake.put("/data/tree/b.txt", []byte("beta"))

	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	expectClass(t, err, transfercore.ClassLimit)
	expectNoResult(t, result)
	if n := fake.callCount("TarOut"); n != 0 {
		t.Fatalf("TarOut ran %d times before the entry refusal", n)
	}
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after the entry refusal")
	}
	noStagingLeft(t, root.Dir())
}

func TestDownloadDirOverBytesRefusedBeforeStaging(t *testing.T) {
	fake := newFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 16
	engine := testEngine(t, fake, limits)
	root := testRoot(t)
	fake.mkdir("/data/tree")
	fake.put("/data/tree/big.bin", binaryContent(4096))

	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	expectClass(t, err, transfercore.ClassLimit)
	expectNoResult(t, result)
	if n := fake.callCount("TarOut"); n != 0 {
		t.Fatalf("TarOut ran %d times before the byte refusal", n)
	}
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after the byte refusal")
	}
	noStagingLeft(t, root.Dir())
}

func TestUploadDirExistsWithoutOverwrite(t *testing.T) {
	fake := newFakeRemote()
	fake.mkdir("/data/out")
	fake.put("/data/out/keep.txt", []byte("kept"))
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	writeLocalFile(t, root, "src/new.txt", []byte("fresh"))

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	expectClass(t, err, transfercore.ClassExists)
	expectNoResult(t, result)
	if got, _ := fake.get("/data/out/keep.txt"); string(got) != "kept" {
		t.Fatal("existing destination file was modified")
	}
	if fake.publishCount() != 0 {
		t.Fatal("publication recorded on refusal")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
	if n := fake.callCount("PublishDir"); n != 1 {
		t.Fatalf("PublishDir ran %d times, want 1", n)
	}
}

func TestUploadDirOverwriteReplaces(t *testing.T) {
	fake := newFakeRemote()
	fake.mkdir("/data/out")
	fake.put("/data/out/old.txt", []byte("old"))
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	newFiles := map[string][]byte{"new.txt": []byte("fresh"), "nested/in.txt": []byte("deep")}
	for name, data := range newFiles {
		writeLocalFile(t, root, "src/"+name, data)
	}

	if _, err := engine.Upload(context.Background(), root, "src", "/data/out", true, nil); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if _, ok := fake.get("/data/out/old.txt"); ok {
		t.Fatal("old destination file survived the overwrite")
	}
	for name, data := range newFiles {
		got, ok := fake.get("/data/out/" + name)
		if !ok || !bytes.Equal(got, data) {
			t.Fatalf("published %s is not byte-exact (present %t)", name, ok)
		}
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

func TestDownloadDirExistsWithoutOverwrite(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	keepPath := writeLocalFile(t, root, "out/keep.txt", []byte("kept"))
	fake.mkdir("/data/tree")
	fake.put("/data/tree/a.txt", []byte("alpha"))
	fake.put("/data/tree/b.txt", []byte("beta"))

	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	expectClass(t, err, transfercore.ClassExists)
	expectNoResult(t, result)
	if got, readErr := os.ReadFile(keepPath); readErr != nil || string(got) != "kept" {
		t.Fatal("existing destination file was modified")
	}
	if n := fake.callCount("TarOut"); n != 0 {
		t.Fatalf("TarOut ran %d times for an existing destination", n)
	}
	noStagingLeft(t, root.Dir())
}

func TestDownloadDirOverwriteReplaces(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	writeLocalFile(t, root, "out/old.txt", []byte("old"))
	remoteFiles := map[string][]byte{"a.txt": []byte("alpha"), "b.txt": []byte("beta")}
	fake.mkdir("/data/tree")
	for name, data := range remoteFiles {
		fake.put("/data/tree/"+name, data)
	}

	if _, err := engine.Download(context.Background(), root, "/data/tree", "out", true, nil); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out", "old.txt")); !os.IsNotExist(statErr) {
		t.Fatal("old destination file survived the overwrite")
	}
	for name, data := range remoteFiles {
		got, readErr := os.ReadFile(filepath.Join(root.Dir(), "out", filepath.FromSlash(name)))
		if readErr != nil || !bytes.Equal(got, data) {
			t.Fatalf("downloaded %s is not byte-exact: %v", name, readErr)
		}
	}
	noStagingLeft(t, root.Dir())
}
