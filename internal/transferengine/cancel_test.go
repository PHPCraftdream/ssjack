package transferengine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestUploadCancelledMidStream(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	writeLocalFile(t, root, "src.bin", binaryContent(2048))
	ctx, cancel := context.WithCancel(context.Background())
	fake.onWriteChunk = cancel

	result, err := engine.Upload(ctx, root, "src.bin", "/data/out.bin", false, nil)
	expectClass(t, err, transfercore.ClassCancelled)
	expectNoResult(t, result)
	cancel()
	if n := fake.callCount("CleanupStaging"); n != 1 {
		t.Fatalf("CleanupStaging ran %d times after cancellation, want 1", n)
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
	if fake.publishCount() != 0 {
		t.Fatal("cancelled upload published the destination")
	}
}

func TestDownloadCancelledMidStream(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	fake.put("/data/remote.bin", binaryContent(2048))
	ctx, cancel := context.WithCancel(context.Background())
	fake.onReadChunk = cancel

	result, err := engine.Download(ctx, root, "/data/remote.bin", "out.bin", false, nil)
	expectClass(t, err, transfercore.ClassCancelled)
	expectNoResult(t, result)
	cancel()
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out.bin")); !os.IsNotExist(statErr) {
		t.Fatal("cancelled download published the destination")
	}
	noStagingLeft(t, root.Dir())
}
