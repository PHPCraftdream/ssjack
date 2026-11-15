package transferengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestUploadHappyPath(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	content := binaryContent(2*32*1024 + 3)
	writeLocalFile(t, root, "src.bin", content)

	var progress []Progress
	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, func(p Progress) {
		progress = append(progress, p)
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	sum := sha256.Sum256(content)
	want := Result{Kind: KindFile, Files: 1, Dirs: 0, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	got, ok := fake.get("/data/out.bin")
	if !ok || !bytes.Equal(got, content) {
		t.Fatal("published remote file is not byte-exact")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
	expectCalls(t, fake, []string{"Probe", "CreateStaging", "WriteFile", "StatFile", "PublishFile", "CleanupStaging"})
	expectPhases(t, progress, int64(len(content)))
	expectContentFree(t, result, err, content, root.Dir())
}

func TestUploadZeroByte(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	writeLocalFile(t, root, "empty.bin", nil)

	result, err := engine.Upload(context.Background(), root, "empty.bin", "/data/empty.bin", false, nil)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if result.Bytes != 0 || result.Files != 1 {
		t.Fatalf("result = %+v", result)
	}
	sum := sha256.Sum256(nil)
	if result.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("SHA256 = %s", result.SHA256)
	}
	got, ok := fake.get("/data/empty.bin")
	if !ok || len(got) != 0 {
		t.Fatal("remote empty file missing")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

func TestUploadHashMismatch(t *testing.T) {
	fake := newFakeRemote()
	fake.corruptStage = true
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	content := binaryContent(4096)
	writeLocalFile(t, root, "src.bin", content)

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	expectClass(t, err, transfercore.ClassIntegrity)
	expectNoResult(t, result)
	if fake.publishCount() != 0 {
		t.Fatal("hash mismatch published the destination")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
	if _, ok := fake.get("/data/out.bin"); ok {
		t.Fatal("destination exists after hash mismatch")
	}
}

func TestUploadSourceChangedSize(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	content := binaryContent(4096)
	sourcePath := writeLocalFile(t, root, "src.bin", content)
	fake.onWriteChunk = func() {
		file, err := os.OpenFile(sourcePath, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Errorf("open source for append: %v", err)
			return
		}
		if _, err := file.WriteString("appended-bytes-16"); err != nil {
			t.Errorf("append to source: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("close source: %v", err)
		}
	}

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	expectClass(t, err, transfercore.ClassIntegrity)
	expectNoResult(t, result)
	if fake.publishCount() != 0 {
		t.Fatal("changed source published the destination")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

func TestUploadOversizeRefusedBeforeMutation(t *testing.T) {
	fake := newFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := testEngine(t, fake, limits)
	root := testRoot(t)
	writeLocalFile(t, root, "big.bin", binaryContent(4096))

	result, err := engine.Upload(context.Background(), root, "big.bin", "/data/out.bin", false, nil)
	expectClass(t, err, transfercore.ClassLimit)
	expectNoResult(t, result)
	if n := fake.callCount("CreateStaging"); n != 0 {
		t.Fatalf("CreateStaging ran %d times before the size refusal", n)
	}
	if n := fake.callCount("Probe"); n != 0 {
		t.Fatalf("Probe ran %d times before the size refusal", n)
	}
}

func TestUploadStreamOverLimit(t *testing.T) {
	fake := newFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := testEngine(t, fake, limits)
	root := testRoot(t)
	sourcePath := writeLocalFile(t, root, "src.bin", binaryContent(1024))
	fake.onWriteChunk = func() {
		file, err := os.OpenFile(sourcePath, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Errorf("open source for append: %v", err)
			return
		}
		if _, err := file.Write(binaryContent(2048)); err != nil {
			t.Errorf("append to source: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("close source: %v", err)
		}
	}

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	expectClass(t, err, transfercore.ClassLimit)
	expectNoResult(t, result)
	if fake.publishCount() != 0 {
		t.Fatal("over-limit upload published the destination")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

func TestUploadExistsWithoutOverwrite(t *testing.T) {
	fake := newFakeRemote()
	fake.put("/data/out.bin", []byte("old content"))
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	content := binaryContent(2048)
	writeLocalFile(t, root, "src.bin", content)

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	expectClass(t, err, transfercore.ClassExists)
	expectNoResult(t, result)
	got, _ := fake.get("/data/out.bin")
	if !bytes.Equal(got, []byte("old content")) {
		t.Fatal("existing destination was modified")
	}
	if fake.publishCount() != 0 {
		t.Fatal("publication recorded on refusal")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

func TestUploadOverwriteReplaces(t *testing.T) {
	fake := newFakeRemote()
	fake.put("/data/out.bin", []byte("old content"))
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	content := binaryContent(2048)
	writeLocalFile(t, root, "src.bin", content)

	if _, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", true, nil); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	got, ok := fake.get("/data/out.bin")
	if !ok || !bytes.Equal(got, content) {
		t.Fatal("destination was not replaced with the new content")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

func TestUploadCleanupFailureKeepsOperationError(t *testing.T) {
	fake := newFakeRemote()
	fake.corruptStage = true
	fake.failCleanup = true
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	writeLocalFile(t, root, "src.bin", binaryContent(2048))

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	expectClass(t, err, transfercore.ClassIntegrity)
	expectNoResult(t, result)
	if n := fake.callCount("CleanupStaging"); n != 1 {
		t.Fatalf("CleanupStaging ran %d times, want 1", n)
	}
}
