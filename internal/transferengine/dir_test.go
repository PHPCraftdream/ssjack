package transferengine

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// dirTreeSpec returns the nested tree shared by the directory round-trip
// tests: file paths relative to the transferred root with their bytes, and
// the directory paths to create (one of them empty).
func dirTreeSpec() (map[string][]byte, []string) {
	files := map[string][]byte{
		"one.bin":             binaryContent(70*1024 + 3),
		"sub/two.txt":         []byte("text with spaces\n"),
		"zero.bin":            nil,
		"name with space.txt": []byte("spacey"),
		"имя-файла.dat":       binaryContent(251),
		"deep/nest/leaf.txt":  []byte("leaf"),
	}
	dirs := []string{"sub", "deep", "deep/nest", "empty"}
	return files, dirs
}

// seedLocalTree creates the spec directories and files under root at rel.
func seedLocalTree(t *testing.T, root *transferlocal.Root, rel string) {
	t.Helper()
	files, dirs := dirTreeSpec()
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(root.Dir(), rel, filepath.FromSlash(dir)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range files {
		writeLocalFile(t, root, rel+"/"+name, data)
	}
}

// seedRemoteTree seeds the same spec tree in the fake under prefix.
func seedRemoteTree(t *testing.T, fake *fakeRemote, prefix string) {
	t.Helper()
	files, dirs := dirTreeSpec()
	for _, dir := range dirs {
		fake.mkdir(prefix + "/" + dir)
	}
	for name, data := range files {
		fake.put(prefix+"/"+name, data)
	}
}

// wantDirResult builds the expected content-free Result for a directory
// transfer of the given manifest.
func wantDirResult(manifest transfercore.Manifest) Result {
	files, dirs, bytes := manifest.Totals()
	return Result{
		Kind:           KindDir,
		Files:          files,
		Dirs:           dirs,
		Bytes:          bytes,
		ManifestSHA256: manifestHex(manifest),
	}
}

func TestUploadDirRoundTrip(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	seedLocalTree(t, root, "src")
	manifest, err := root.WalkSource("src", transfercore.DefaultLimits())
	if err != nil {
		t.Fatalf("WalkSource: %v", err)
	}

	var progress []Progress
	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, func(p Progress) {
		progress = append(progress, p)
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	want := wantDirResult(manifest)
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	files, _ := dirTreeSpec()
	for name, data := range files {
		got, ok := fake.get("/data/out/" + name)
		if !ok || !bytes.Equal(got, data) {
			t.Fatalf("published %s is not byte-exact (present %t)", name, ok)
		}
	}
	expectCalls(t, fake, []string{"Probe", "CreateStaging", "TarIn", "VerifyTree", "PublishDir", "CleanupStaging"})
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
	if fake.publishCount() != 1 {
		t.Fatalf("publishCount = %d, want 1", fake.publishCount())
	}
	if n := fake.callCount("CleanupStaging"); n != 1 {
		t.Fatalf("CleanupStaging ran %d times, want 1", n)
	}
	_, _, totalBytes := manifest.Totals()
	expectPhases(t, progress, totalBytes)
	expectContentFree(t, result, err, files["one.bin"], root.Dir())
}

func TestDownloadDirRoundTrip(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	seedRemoteTree(t, fake, "/data/tree")
	seedLocalTree(t, root, "expected")
	manifest, walkErr := root.WalkSource("expected", transfercore.DefaultLimits())
	if walkErr != nil {
		t.Fatalf("WalkSource: %v", walkErr)
	}

	var progress []Progress
	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, func(p Progress) {
		progress = append(progress, p)
	})
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	want := wantDirResult(manifest)
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	files, _ := dirTreeSpec()
	for name, data := range files {
		got, readErr := os.ReadFile(filepath.Join(root.Dir(), "out", filepath.FromSlash(name)))
		if readErr != nil || !bytes.Equal(got, data) {
			t.Fatalf("downloaded %s is not byte-exact: %v", name, readErr)
		}
	}
	if info, statErr := os.Stat(filepath.Join(root.Dir(), "out", "empty")); statErr != nil || !info.IsDir() {
		t.Fatalf("downloaded empty directory is missing: %v", statErr)
	}
	expectCalls(t, fake, []string{"Probe", "StatFile", "PreflightTree", "TarOut"})
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
	noStagingLeft(t, root.Dir())
	_, _, totalBytes := manifest.Totals()
	expectPhases(t, progress, totalBytes)
	expectContentFree(t, result, err, files["one.bin"], root.Dir())
}

func TestUploadDirEmpty(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	if err := os.MkdirAll(filepath.Join(root.Dir(), "empty"), 0o700); err != nil {
		t.Fatal(err)
	}

	result, err := engine.Upload(context.Background(), root, "empty", "/data/out", false, nil)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	want := wantDirResult(transfercore.Manifest{})
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
	if fake.publishCount() != 1 {
		t.Fatalf("publishCount = %d, want 1", fake.publishCount())
	}
	if !fake.dirs["/data/out"] {
		t.Fatal("remote destination directory was not created")
	}
}

func TestDownloadDirEmpty(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	fake.mkdir("/data/empty")

	result, err := engine.Download(context.Background(), root, "/data/empty", "out", false, nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	want := wantDirResult(transfercore.Manifest{})
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	if info, statErr := os.Stat(filepath.Join(root.Dir(), "out")); statErr != nil || !info.IsDir() {
		t.Fatalf("destination is missing or not a directory: %v", statErr)
	}
	noStagingLeft(t, root.Dir())
}

func TestUploadDirDirsOnly(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	if err := os.MkdirAll(filepath.Join(root.Dir(), "src", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}

	manifest, walkErr := root.WalkSource("src", transfercore.DefaultLimits())
	if walkErr != nil {
		t.Fatalf("WalkSource: %v", walkErr)
	}
	if files, dirs, _ := manifest.Totals(); files != 0 || dirs != 1 {
		t.Fatalf("walk = %d files, %d dirs, want 0 files, 1 dir", files, dirs)
	}

	result, err := engine.Upload(context.Background(), root, "src", "/data/out", false, nil)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	want := wantDirResult(manifest)
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	if !fake.dirs["/data/out/nested"] {
		t.Fatal("remote destination directory was not created")
	}
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
	if fake.publishCount() != 1 {
		t.Fatalf("publishCount = %d, want 1", fake.publishCount())
	}
}

func TestDownloadDirDirsOnly(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	fake.mkdir("/data/tree/nested")
	if err := os.MkdirAll(filepath.Join(root.Dir(), "expected", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, walkErr := root.WalkSource("expected", transfercore.DefaultLimits())
	if walkErr != nil {
		t.Fatalf("WalkSource: %v", walkErr)
	}

	result, err := engine.Download(context.Background(), root, "/data/tree", "out", false, nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	want := wantDirResult(manifest)
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	if info, statErr := os.Stat(filepath.Join(root.Dir(), "out", "nested")); statErr != nil || !info.IsDir() {
		t.Fatalf("downloaded nested directory is missing: %v", statErr)
	}
	noStagingLeft(t, root.Dir())
	if fake.stagingCount() != 0 {
		t.Fatalf("remote staging left behind: %d", fake.stagingCount())
	}
}

// manifestHex returns the hex manifest digest the engine reports.
func manifestHex(m transfercore.Manifest) string {
	digest := m.Digest()
	return hex.EncodeToString(digest[:])
}
