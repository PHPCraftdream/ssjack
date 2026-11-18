package streamtest

import (
	"context"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"os"
	"path/filepath"
	"testing"
)

func TestUploadCancelledMidStream(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "src.bin", testfixture.BinaryContent(2048))
	ctx, cancel := context.WithCancel(context.Background())
	fake.OnWriteChunk = cancel

	result, err := engine.Upload(ctx, root, "src.bin", "/data/out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassCancelled)
	enginetest.ExpectNoResult(t, result)
	cancel()
	if n := fake.CallCount("CleanupStaging"); n != 1 {
		t.Fatalf("CleanupStaging ran %d times after cancellation, want 1", n)
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
	if fake.PublishCount() != 0 {
		t.Fatal("cancelled upload published the destination")
	}
}

func TestDownloadCancelledMidStream(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	fake.Put("/data/remote.bin", testfixture.BinaryContent(2048))
	ctx, cancel := context.WithCancel(context.Background())
	fake.OnReadChunk = cancel

	result, err := engine.Download(ctx, root, "/data/remote.bin", "out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassCancelled)
	enginetest.ExpectNoResult(t, result)
	cancel()
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out.bin")); !os.IsNotExist(statErr) {
		t.Fatal("cancelled download published the destination")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}
