package streamtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"os"
	"testing"
)

func TestUploadHappyPath(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	content := testfixture.BinaryContent(2*32*1024 + 3)
	testfixture.WriteLocalFile(t, root, "src.bin", content)

	var progress []transferengine.Progress
	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, func(p transferengine.Progress) {
		progress = append(progress, p)
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	sum := sha256.Sum256(content)
	want := transferengine.Result{Kind: transferengine.KindFile, Files: 1, Dirs: 0, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	got, ok := fake.Get("/data/out.bin")
	if !ok || !bytes.Equal(got, content) {
		t.Fatal("published remote file is not byte-exact")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
	testfixture.ExpectCalls(t, fake, []string{"Probe", "CreateStaging", "WriteFile", "StatFile", "PublishFile", "CleanupStaging"})
	enginetest.ExpectPhases(t, progress, int64(len(content)))
	enginetest.ExpectContentFree(t, result, err, content, root.Dir())
}

func TestUploadZeroByte(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "empty.bin", nil)

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
	got, ok := fake.Get("/data/empty.bin")
	if !ok || len(got) != 0 {
		t.Fatal("remote empty file missing")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
}

func TestUploadHashMismatch(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.CorruptStage = true
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	content := testfixture.BinaryContent(4096)
	testfixture.WriteLocalFile(t, root, "src.bin", content)

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	enginetest.ExpectNoResult(t, result)
	if fake.PublishCount() != 0 {
		t.Fatal("hash mismatch published the destination")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
	if _, ok := fake.Get("/data/out.bin"); ok {
		t.Fatal("destination exists after hash mismatch")
	}
}

func TestUploadSourceChangedSize(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	content := testfixture.BinaryContent(4096)
	sourcePath := testfixture.WriteLocalFile(t, root, "src.bin", content)
	fake.OnWriteChunk = func() {
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
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	enginetest.ExpectNoResult(t, result)
	if fake.PublishCount() != 0 {
		t.Fatal("changed source published the destination")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
}

func TestUploadOversizeRefusedBeforeMutation(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := enginetest.TestEngine(t, fake, limits)
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "big.bin", testfixture.BinaryContent(4096))

	result, err := engine.Upload(context.Background(), root, "big.bin", "/data/out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassLimit)
	enginetest.ExpectNoResult(t, result)
	if n := fake.CallCount("CreateStaging"); n != 0 {
		t.Fatalf("CreateStaging ran %d times before the size refusal", n)
	}
	if n := fake.CallCount("Probe"); n != 0 {
		t.Fatalf("Probe ran %d times before the size refusal", n)
	}
}

func TestUploadStreamOverLimit(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := enginetest.TestEngine(t, fake, limits)
	root := enginetest.TestRoot(t)
	sourcePath := testfixture.WriteLocalFile(t, root, "src.bin", testfixture.BinaryContent(1024))
	fake.OnWriteChunk = func() {
		file, err := os.OpenFile(sourcePath, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Errorf("open source for append: %v", err)
			return
		}
		if _, err := file.Write(testfixture.BinaryContent(2048)); err != nil {
			t.Errorf("append to source: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("close source: %v", err)
		}
	}

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassLimit)
	enginetest.ExpectNoResult(t, result)
	if fake.PublishCount() != 0 {
		t.Fatal("over-limit upload published the destination")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
}

func TestUploadExistsWithoutOverwrite(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.Put("/data/out.bin", []byte("old content"))
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	content := testfixture.BinaryContent(2048)
	testfixture.WriteLocalFile(t, root, "src.bin", content)

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassExists)
	enginetest.ExpectNoResult(t, result)
	got, _ := fake.Get("/data/out.bin")
	if !bytes.Equal(got, []byte("old content")) {
		t.Fatal("existing destination was modified")
	}
	if fake.PublishCount() != 0 {
		t.Fatal("publication recorded on refusal")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
}

func TestUploadOverwriteReplaces(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.Put("/data/out.bin", []byte("old content"))
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	content := testfixture.BinaryContent(2048)
	testfixture.WriteLocalFile(t, root, "src.bin", content)

	if _, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", true, nil); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	got, ok := fake.Get("/data/out.bin")
	if !ok || !bytes.Equal(got, content) {
		t.Fatal("destination was not replaced with the new content")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
}

func TestUploadCleanupFailureKeepsOperationError(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.CorruptStage = true
	fake.FailCleanup = true
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "src.bin", testfixture.BinaryContent(2048))

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	enginetest.ExpectNoResult(t, result)
	if n := fake.CallCount("CleanupStaging"); n != 1 {
		t.Fatalf("CleanupStaging ran %d times, want 1", n)
	}
}
