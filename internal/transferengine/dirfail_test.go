package transferengine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// expectFinish runs op on a goroutine and fails the test if it has not
// returned within the deadline, so a tar-pipe deadlock cannot hang CI.
func expectFinish(t *testing.T, deadline time.Duration, op func() (Result, error)) (Result, error) {
	t.Helper()
	type outcome struct {
		result Result
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
		return Result{}, nil
	}
}

func TestUploadDirSourceChangedBeforeStream(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	sourcePath := writeLocalFile(t, root, "src/big.bin", binaryContent(4096))
	fake.onCreateStaging = func() {
		file, err := os.OpenFile(sourcePath, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Errorf("open source for append: %v", err)
			return
		}
		if _, err := file.Write(binaryContent(32)); err != nil {
			t.Errorf("append to source: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("close source: %v", err)
		}
	}

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	expectClass(t, err, transfercore.ClassIntegrity)
	expectNoResult(t, result)
	if fake.publishCount() != 0 {
		t.Fatal("changed source published the destination")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

func TestUploadDirVerifyMismatch(t *testing.T) {
	fake := newFakeRemote()
	fake.corruptTree = true
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	writeLocalFile(t, root, "src/a.txt", []byte("alpha"))
	writeLocalFile(t, root, "src/b.txt", []byte("beta"))

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	expectClass(t, err, transfercore.ClassIntegrity)
	expectNoResult(t, result)
	if fake.publishCount() != 0 {
		t.Fatal("mismatched tree published the destination")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

func TestDownloadDirRemoteChangedDuringTransfer(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	fake.mkdir("/data/tree")
	fake.put("/data/tree/f.bin", binaryContent(4096))
	fake.onTarOutStart = func() {
		fake.put("/data/tree/f.bin", binaryContent(2048))
	}

	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	expectClass(t, err, transfercore.ClassIntegrity)
	expectNoResult(t, result)
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after integrity failure")
	}
	noStagingLeft(t, root.Dir())
}

func TestUploadDirCancelledMidStream(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	specFiles := map[string][]byte{"big.bin": binaryContent(64 << 10), "small.txt": []byte("s")}
	for name, data := range specFiles {
		writeLocalFile(t, root, "src/"+name, data)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fake.onTarInChunk = cancel

	result, err := engine.Upload(ctx, root, "src", "/data/out", false, nil)
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
	for name := range specFiles {
		if _, ok := fake.get("/data/out/" + name); ok {
			t.Fatalf("cancelled upload published %s", name)
		}
	}
}

func TestDownloadDirCancelledMidStream(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	fake.mkdir("/data/tree")
	fake.put("/data/tree/big.bin", binaryContent(64<<10))
	fake.put("/data/tree/small.txt", []byte("s"))
	ctx, cancel := context.WithCancel(context.Background())
	fake.onTarOutChunk = cancel

	result, err := engine.Download(ctx, root, "/data/tree", "out", false, nil)
	expectClass(t, err, transfercore.ClassCancelled)
	expectNoResult(t, result)
	cancel()
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("cancelled download published the destination")
	}
	noStagingLeft(t, root.Dir())
}

func TestUploadDirTarInFailureUnblocksProducer(t *testing.T) {
	fake := newFakeRemote()
	fake.failTarIn = transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	writeLocalFile(t, root, "src/big.bin", binaryContent(64<<10))

	result, err := expectFinish(t, 30*time.Second, func() (Result, error) {
		return engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	})
	expectClass(t, err, transfercore.ClassRefusedPath)
	expectNoResult(t, result)
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
	if fake.publishCount() != 0 {
		t.Fatal("refused upload published the destination")
	}
}

func TestDownloadDirTarOutFailureUnblocksConsumer(t *testing.T) {
	fake := newFakeRemote()
	fake.failTarOut = transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	fake.mkdir("/data/tree")
	fake.put("/data/tree/big.bin", binaryContent(64<<10))
	fake.put("/data/tree/small.txt", []byte("s"))

	// The TarOut refusal closes the pipe before the extractor reads
	// anything, so the extraction verdict for the truncated stream
	// (integrity) surfaces; the deadline guards that both pipe sides still
	// finish without deadlocking.
	result, err := expectFinish(t, 30*time.Second, func() (Result, error) {
		return engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	})
	expectClass(t, err, transfercore.ClassIntegrity)
	expectNoResult(t, result)
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after a refused stream")
	}
	noStagingLeft(t, root.Dir())
}
