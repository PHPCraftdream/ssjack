package treetest

import (
	"bytes"
	"context"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"os"
	"path/filepath"
	"testing"
)

func TestUploadDirOverEntriesRefusedBeforeRemote(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxEntries = 3
	engine := enginetest.TestEngine(t, fake, limits)
	root := enginetest.TestRoot(t)
	for _, name := range []string{"a.txt", "b.txt", "c.txt", "d.txt"} {
		testfixture.WriteLocalFile(t, root, "src/"+name, []byte("x"))
	}

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassLimit)
	enginetest.ExpectNoResult(t, result)
	if n := fake.CallCount("Probe"); n != 0 {
		t.Fatalf("Probe ran %d times before the entry refusal", n)
	}
	if n := fake.CallCount("CreateStaging"); n != 0 {
		t.Fatalf("CreateStaging ran %d times before the entry refusal", n)
	}
}

func TestUploadDirOverBytesRefusedBeforeRemote(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := enginetest.TestEngine(t, fake, limits)
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "src/big.bin", testfixture.BinaryContent(4096))

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassLimit)
	enginetest.ExpectNoResult(t, result)
	if n := fake.CallCount("Probe"); n != 0 {
		t.Fatalf("Probe ran %d times before the byte refusal", n)
	}
	if n := fake.CallCount("CreateStaging"); n != 0 {
		t.Fatalf("CreateStaging ran %d times before the byte refusal", n)
	}
}

func TestUploadDirStreamOverLimit(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 64
	engine := enginetest.TestEngine(t, fake, limits)
	root := enginetest.TestRoot(t)
	// The walk passes (40 bytes); the tar stream (512-byte header plus
	// padding) crosses the limit only while streaming.
	testfixture.WriteLocalFile(t, root, "src/mid.bin", testfixture.BinaryContent(40))

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassLimit)
	enginetest.ExpectNoResult(t, result)
	if fake.PublishCount() != 0 {
		t.Fatal("over-limit upload published the destination")
	}
	if n := fake.CallCount("VerifyTree"); n != 0 {
		t.Fatalf("VerifyTree ran %d times after a stream limit failure", n)
	}
	if n := fake.CallCount("PublishDir"); n != 0 {
		t.Fatalf("PublishDir ran %d times after a stream limit failure", n)
	}
	if n := fake.CallCount("CleanupStaging"); n != 1 {
		t.Fatalf("CleanupStaging ran %d times, want 1", n)
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
}

func TestDownloadDirOverEntriesRefusedBeforeStaging(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxEntries = 1
	engine := enginetest.TestEngine(t, fake, limits)
	root := enginetest.TestRoot(t)
	fake.Mkdir("/data/tree")
	fake.Put("/data/tree/a.txt", []byte("alpha"))
	fake.Put("/data/tree/b.txt", []byte("beta"))

	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassLimit)
	enginetest.ExpectNoResult(t, result)
	if n := fake.CallCount("TarOut"); n != 0 {
		t.Fatalf("TarOut ran %d times before the entry refusal", n)
	}
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after the entry refusal")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestDownloadDirOverBytesRefusedBeforeStaging(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 16
	engine := enginetest.TestEngine(t, fake, limits)
	root := enginetest.TestRoot(t)
	fake.Mkdir("/data/tree")
	fake.Put("/data/tree/big.bin", testfixture.BinaryContent(4096))

	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassLimit)
	enginetest.ExpectNoResult(t, result)
	if n := fake.CallCount("TarOut"); n != 0 {
		t.Fatalf("TarOut ran %d times before the byte refusal", n)
	}
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after the byte refusal")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestUploadDirExistsWithoutOverwrite(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.Mkdir("/data/out")
	fake.Put("/data/out/keep.txt", []byte("kept"))
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "src/new.txt", []byte("fresh"))

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassExists)
	enginetest.ExpectNoResult(t, result)
	if got, _ := fake.Get("/data/out/keep.txt"); string(got) != "kept" {
		t.Fatal("existing destination file was modified")
	}
	if fake.PublishCount() != 0 {
		t.Fatal("publication recorded on refusal")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
	if n := fake.CallCount("PublishDir"); n != 1 {
		t.Fatalf("PublishDir ran %d times, want 1", n)
	}
}

func TestUploadDirOverwriteReplaces(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.Mkdir("/data/out")
	fake.Put("/data/out/old.txt", []byte("old"))
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	newFiles := map[string][]byte{"new.txt": []byte("fresh"), "nested/in.txt": []byte("deep")}
	for name, data := range newFiles {
		testfixture.WriteLocalFile(t, root, "src/"+name, data)
	}

	if _, err := engine.Upload(context.Background(), root, "src", "/data/out", true, nil); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if _, ok := fake.Get("/data/out/old.txt"); ok {
		t.Fatal("old destination file survived the overwrite")
	}
	for name, data := range newFiles {
		got, ok := fake.Get("/data/out/" + name)
		if !ok || !bytes.Equal(got, data) {
			t.Fatalf("published %s is not byte-exact (present %t)", name, ok)
		}
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
}

func TestDownloadDirExistsWithoutOverwrite(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	keepPath := testfixture.WriteLocalFile(t, root, "out/keep.txt", []byte("kept"))
	fake.Mkdir("/data/tree")
	fake.Put("/data/tree/a.txt", []byte("alpha"))
	fake.Put("/data/tree/b.txt", []byte("beta"))

	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassExists)
	enginetest.ExpectNoResult(t, result)
	if got, readErr := os.ReadFile(keepPath); readErr != nil || string(got) != "kept" {
		t.Fatal("existing destination file was modified")
	}
	if n := fake.CallCount("TarOut"); n != 0 {
		t.Fatalf("TarOut ran %d times for an existing destination", n)
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestDownloadDirOverwriteReplaces(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "out/old.txt", []byte("old"))
	remoteFiles := map[string][]byte{"a.txt": []byte("alpha"), "b.txt": []byte("beta")}
	fake.Mkdir("/data/tree")
	for name, data := range remoteFiles {
		fake.Put("/data/tree/"+name, data)
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
	testfixture.NoStagingLeft(t, root.Dir())
}
