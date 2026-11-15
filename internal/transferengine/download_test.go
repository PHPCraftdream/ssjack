package transferengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestDownloadHappyPath(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	content := binaryContent(2*32*1024 + 3)
	fake.put("/data/remote.bin", content)
	writeLocalFile(t, root, "sub/keep.txt", []byte("x"))

	var progress []Progress
	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "sub/out.bin", false, func(p Progress) {
		progress = append(progress, p)
	})
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	sum := sha256.Sum256(content)
	want := Result{Kind: KindFile, Files: 1, Dirs: 0, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	got, err := os.ReadFile(filepath.Join(root.Dir(), "sub", "out.bin"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("downloaded file is not byte-exact")
	}
	noStagingLeft(t, root.Dir())
	expectCalls(t, fake, []string{"Probe", "StatFile", "ReadFile"})
	expectPhases(t, progress, int64(len(content)))
	expectContentFree(t, result, err, content, root.Dir())
}

func TestDownloadZeroByte(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	fake.put("/data/empty.bin", nil)

	result, err := engine.Download(context.Background(), root, "/data/empty.bin", "empty.bin", false, nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	sum := sha256.Sum256(nil)
	want := Result{Kind: KindFile, Files: 1, Dirs: 0, Bytes: 0, SHA256: hex.EncodeToString(sum[:])}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	noStagingLeft(t, root.Dir())
}

func TestDownloadRemoteChangedMidStream(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	fake.put("/data/remote.bin", binaryContent(4096))
	fake.onReadStart = func() {
		fake.put("/data/remote.bin", binaryContent(4095))
	}

	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", false, nil)
	expectClass(t, err, transfercore.ClassIntegrity)
	expectNoResult(t, result)
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out.bin")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after integrity failure")
	}
	noStagingLeft(t, root.Dir())
}

func TestDownloadOversizeRefusedBeforeStaging(t *testing.T) {
	fake := newFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := testEngine(t, fake, limits)
	root := testRoot(t)
	fake.put("/data/remote.bin", binaryContent(4096))

	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", false, nil)
	expectClass(t, err, transfercore.ClassLimit)
	expectNoResult(t, result)
	if n := fake.callCount("ReadFile"); n != 0 {
		t.Fatalf("ReadFile ran %d times before the size refusal", n)
	}
	noStagingLeft(t, root.Dir())
}

func TestDownloadStreamOverLimit(t *testing.T) {
	fake := newFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := testEngine(t, fake, limits)
	root := testRoot(t)
	fake.put("/data/remote.bin", binaryContent(1024))
	fake.onReadStart = func() {
		fake.put("/data/remote.bin", binaryContent(4096))
	}

	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", false, nil)
	expectClass(t, err, transfercore.ClassLimit)
	expectNoResult(t, result)
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out.bin")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after limit failure")
	}
	noStagingLeft(t, root.Dir())
}

func TestDownloadExistsWithoutOverwrite(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	fake.put("/data/remote.bin", binaryContent(2048))
	existing := writeLocalFile(t, root, "out.bin", []byte("kept"))

	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", false, nil)
	expectClass(t, err, transfercore.ClassExists)
	expectNoResult(t, result)
	got, err := os.ReadFile(existing)
	if err != nil || !bytes.Equal(got, []byte("kept")) {
		t.Fatal("existing destination was modified")
	}
	noStagingLeft(t, root.Dir())
}

func TestDownloadOverwriteReplaces(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	content := binaryContent(2048)
	fake.put("/data/remote.bin", content)
	writeLocalFile(t, root, "out.bin", []byte("old"))

	if _, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", true, nil); err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root.Dir(), "out.bin"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("destination was not replaced with the downloaded content")
	}
	noStagingLeft(t, root.Dir())
}
