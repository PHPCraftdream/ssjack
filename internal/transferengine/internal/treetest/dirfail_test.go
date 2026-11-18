package treetest

import (
	"context"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// expectFinish runs op on a goroutine and fails the test if it has not
// returned within the deadline, so a tar-pipe deadlock cannot hang CI.
func expectFinish(t *testing.T, deadline time.Duration, op func() (transferengine.Result, error)) (transferengine.Result, error) {
	t.Helper()
	type outcome struct {
		result transferengine.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := op()
		done <- outcome{result: result, err: err}
		close(done)
	}()
	select {
	case o := <-done:
		return o.result, o.err
	case <-time.After(deadline):
		t.Fatalf("operation did not finish within %s", deadline)
		return transferengine.Result{}, nil
	}
}

func TestUploadDirSourceChangedBeforeStream(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	sourcePath := testfixture.WriteLocalFile(t, root, "src/big.bin", testfixture.BinaryContent(4096))
	fake.OnCreateStaging = func() {
		file, err := os.OpenFile(sourcePath, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Errorf("open source for append: %v", err)
			return
		}
		if _, err := file.Write(testfixture.BinaryContent(32)); err != nil {
			t.Errorf("append to source: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("close source: %v", err)
		}
	}

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	enginetest.ExpectNoResult(t, result)
	if fake.PublishCount() != 0 {
		t.Fatal("changed source published the destination")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
}

func TestUploadDirVerifyMismatch(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.CorruptTree = true
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "src/a.txt", []byte("alpha"))
	testfixture.WriteLocalFile(t, root, "src/b.txt", []byte("beta"))

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	enginetest.ExpectNoResult(t, result)
	if fake.PublishCount() != 0 {
		t.Fatal("mismatched tree published the destination")
	}
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
}

func TestDownloadDirRemoteChangedDuringTransfer(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	fake.Mkdir("/data/tree")
	fake.Put("/data/tree/f.bin", testfixture.BinaryContent(4096))
	fake.OnTarOutStart = func() {
		fake.Put("/data/tree/f.bin", testfixture.BinaryContent(2048))
	}

	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	enginetest.ExpectNoResult(t, result)
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after integrity failure")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestUploadDirCancelledMidStream(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	specFiles := map[string][]byte{"big.bin": testfixture.BinaryContent(64 << 10), "small.txt": []byte("s")}
	for name, data := range specFiles {
		testfixture.WriteLocalFile(t, root, "src/"+name, data)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fake.OnTarInChunk = cancel

	result, err := engine.Upload(ctx, root, "src", "/data/out", false, nil)
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
	for name := range specFiles {
		if _, ok := fake.Get("/data/out/" + name); ok {
			t.Fatalf("cancelled upload published %s", name)
		}
	}
}

func TestDownloadDirCancelledMidStream(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	fake.Mkdir("/data/tree")
	fake.Put("/data/tree/big.bin", testfixture.BinaryContent(64<<10))
	fake.Put("/data/tree/small.txt", []byte("s"))
	ctx, cancel := context.WithCancel(context.Background())
	fake.OnTarOutChunk = cancel

	result, err := engine.Download(ctx, root, "/data/tree", "out", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassCancelled)
	enginetest.ExpectNoResult(t, result)
	cancel()
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("cancelled download published the destination")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestUploadDirTarInFailureUnblocksProducer(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.FailTarIn = transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "src/big.bin", testfixture.BinaryContent(64<<10))

	result, err := expectFinish(t, 30*time.Second, func() (transferengine.Result, error) {
		return engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	})
	testfixture.ExpectClass(t, err, transfercore.ClassRefusedPath)
	enginetest.ExpectNoResult(t, result)
	if fake.StagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.StagingCount())
	}
	if fake.PublishCount() != 0 {
		t.Fatal("refused upload published the destination")
	}
}

func TestDownloadDirTarOutFailureUnblocksConsumer(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.FailTarOut = transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	fake.Mkdir("/data/tree")
	fake.Put("/data/tree/big.bin", testfixture.BinaryContent(64<<10))
	fake.Put("/data/tree/small.txt", []byte("s"))

	// The TarOut refusal closes the pipe before the extractor reads
	// anything, so the extraction verdict for the truncated stream
	// (integrity) surfaces; the deadline guards that both pipe sides still
	// finish without deadlocking.
	result, err := expectFinish(t, 30*time.Second, func() (transferengine.Result, error) {
		return engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	})
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	enginetest.ExpectNoResult(t, result)
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after a refused stream")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}
