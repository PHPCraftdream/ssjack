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
	"path/filepath"
	"testing"
)

func TestDownloadHappyPath(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	content := testfixture.BinaryContent(2*32*1024 + 3)
	fake.Put("/data/remote.bin", content)
	testfixture.WriteLocalFile(t, root, "sub/keep.txt", []byte("x"))

	var progress []transferengine.Progress
	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "sub/out.bin", false, func(p transferengine.Progress) {
		progress = append(progress, p)
	})
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	sum := sha256.Sum256(content)
	want := transferengine.Result{Kind: transferengine.KindFile, Files: 1, Dirs: 0, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	got, err := os.ReadFile(filepath.Join(root.Dir(), "sub", "out.bin"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("downloaded file is not byte-exact")
	}
	testfixture.NoStagingLeft(t, root.Dir())
	testfixture.ExpectCalls(t, fake, []string{"Probe", "StatFile", "ReadFile"})
	enginetest.ExpectPhases(t, progress, int64(len(content)))
	enginetest.ExpectContentFree(t, result, err, content, root.Dir())
}

func TestDownloadZeroByte(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	fake.Put("/data/empty.bin", nil)

	result, err := engine.Download(context.Background(), root, "/data/empty.bin", "empty.bin", false, nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	sum := sha256.Sum256(nil)
	want := transferengine.Result{Kind: transferengine.KindFile, Files: 1, Dirs: 0, Bytes: 0, SHA256: hex.EncodeToString(sum[:])}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestDownloadRemoteChangedMidStream(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	fake.Put("/data/remote.bin", testfixture.BinaryContent(4096))
	fake.OnReadStart = func() {
		fake.Put("/data/remote.bin", testfixture.BinaryContent(4095))
	}

	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	enginetest.ExpectNoResult(t, result)
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out.bin")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after integrity failure")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestDownloadOversizeRefusedBeforeStaging(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := enginetest.TestEngine(t, fake, limits)
	root := enginetest.TestRoot(t)
	fake.Put("/data/remote.bin", testfixture.BinaryContent(4096))

	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassLimit)
	enginetest.ExpectNoResult(t, result)
	if n := fake.CallCount("ReadFile"); n != 0 {
		t.Fatalf("ReadFile ran %d times before the size refusal", n)
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestDownloadStreamOverLimit(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	limits := transfercore.DefaultLimits()
	limits.MaxBytes = 1024
	engine := enginetest.TestEngine(t, fake, limits)
	root := enginetest.TestRoot(t)
	fake.Put("/data/remote.bin", testfixture.BinaryContent(1024))
	fake.OnReadStart = func() {
		fake.Put("/data/remote.bin", testfixture.BinaryContent(4096))
	}

	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassLimit)
	enginetest.ExpectNoResult(t, result)
	if _, statErr := os.Lstat(filepath.Join(root.Dir(), "out.bin")); !os.IsNotExist(statErr) {
		t.Fatal("destination exists after limit failure")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestDownloadExistsWithoutOverwrite(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	fake.Put("/data/remote.bin", testfixture.BinaryContent(2048))
	existing := testfixture.WriteLocalFile(t, root, "out.bin", []byte("kept"))

	result, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassExists)
	enginetest.ExpectNoResult(t, result)
	got, err := os.ReadFile(existing)
	if err != nil || !bytes.Equal(got, []byte("kept")) {
		t.Fatal("existing destination was modified")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}

func TestDownloadOverwriteReplaces(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	content := testfixture.BinaryContent(2048)
	fake.Put("/data/remote.bin", content)
	testfixture.WriteLocalFile(t, root, "out.bin", []byte("old"))

	if _, err := engine.Download(context.Background(), root, "/data/remote.bin", "out.bin", true, nil); err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root.Dir(), "out.bin"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("destination was not replaced with the downloaded content")
	}
	testfixture.NoStagingLeft(t, root.Dir())
}
