//go:build linux

package streamtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// shStreamRunner runs fixed command templates through a local `sh -c`,
// byte-exact like the SSH StreamRunner it replaces.
func shStreamRunner() remote.StreamRunner {
	return func(ctx context.Context, target string, command string, stdin io.Reader, stdout io.Writer, stderr io.Writer) (int, error) {
		cmd := exec.CommandContext(ctx, "sh", "-c", command)
		if stdin != nil {
			cmd.Stdin = stdin
		}
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return exitErr.ExitCode(), nil
			}
			return -1, err
		}
		return 0, nil
	}
}

// linuxWantDirResult walks root at rel and builds the expected directory
// transferengine.Result of a successful round trip.
func linuxWantDirResult(t *testing.T, root *transferlocal.Root, rel string) transferengine.Result {
	t.Helper()
	manifest, err := root.WalkSource(rel, transfercore.DefaultLimits())
	if err != nil {
		t.Fatalf("walk %s: %v", rel, err)
	}
	files, dirs, bytes := manifest.Totals()
	digest := manifest.Digest()
	return transferengine.Result{
		Kind:           transferengine.KindDir,
		Files:          files,
		Dirs:           dirs,
		Bytes:          bytes,
		ManifestSHA256: hex.EncodeToString(digest[:]),
	}
}

// linuxVerifyTree compares a transferred tree byte-exactly against the spec.
func linuxVerifyTree(t *testing.T, gotRoot string, dirs []string, files map[string][]byte) {
	t.Helper()
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(gotRoot, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("file %s content mismatch (%d bytes, want %d)", name, len(got), len(want))
		}
	}
	for _, dir := range dirs {
		info, err := os.Stat(filepath.Join(gotRoot, filepath.FromSlash(dir)))
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
	}
}

// linuxTreeSpec returns the nested tree exercised by the round-trip tests.
func linuxTreeSpec() (map[string][]byte, []string) {
	files := map[string][]byte{
		"one.bin":             testfixture.BinaryContent(70000 + 3),
		"sub/two.txt":         []byte("text with spaces\n"),
		"zero.bin":            nil,
		"name with space.txt": []byte("spacey"),
		"имя-файла.dat":       testfixture.BinaryContent(251),
	}
	dirs := []string{"sub", "empty"}
	return files, dirs
}

func TestLinuxFileRoundTrip(t *testing.T) {
	ctx := context.Background()
	engine := enginetest.TestEngine(t, transferremote.New(shStreamRunner(), "t", transfercore.DefaultLimits()), transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	remoteDir := t.TempDir()

	content := testfixture.BinaryContent(2*32*1024 + 3)
	testfixture.WriteLocalFile(t, root, "in.bin", content)
	remote := filepath.ToSlash(filepath.Join(remoteDir, "out.bin"))

	result, err := engine.Upload(ctx, root, "in.bin", remote, false, nil)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	sum := sha256.Sum256(content)
	want := transferengine.Result{Kind: transferengine.KindFile, Files: 1, Dirs: 0, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
	if result != want {
		t.Fatalf("upload result = %+v, want %+v", result, want)
	}
	got, err := os.ReadFile(remote)
	if err != nil {
		t.Fatalf("read published remote file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("published remote file content mismatch (%d bytes, want %d)", len(got), len(content))
	}

	result, err = engine.Download(ctx, root, remote, "got.bin", false, nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if result != want {
		t.Fatalf("download result = %+v, want %+v", result, want)
	}
	got, err = os.ReadFile(filepath.Join(root.Dir(), "got.bin"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("downloaded file content mismatch (%d bytes, want %d)", len(got), len(content))
	}

	testfixture.NoStagingLeft(t, root.Dir())
	testfixture.NoStagingLeft(t, remoteDir)
	enginetest.ExpectContentFree(t, result, err, content, root.Dir())
	if repr := fmt.Sprintf("%+v", result); strings.Contains(repr, remoteDir) {
		t.Fatalf("result contains the remote path: %s", repr)
	}
}

func TestLinuxDirUploadRoundTrip(t *testing.T) {
	ctx := context.Background()
	engine := enginetest.TestEngine(t, transferremote.New(shStreamRunner(), "t", transfercore.DefaultLimits()), transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	remoteDir := t.TempDir()

	files, dirs := linuxTreeSpec()
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(root.Dir(), "src", filepath.FromSlash(dir)), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	for name, data := range files {
		testfixture.WriteLocalFile(t, root, "src/"+name, data)
	}
	remote := filepath.ToSlash(filepath.Join(remoteDir, "published"))

	result, err := engine.Upload(ctx, root, "src", remote, false, nil)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	want := linuxWantDirResult(t, root, "src")
	if result != want {
		t.Fatalf("upload result = %+v, want %+v", result, want)
	}
	linuxVerifyTree(t, remote, dirs, files)

	testfixture.NoStagingLeft(t, root.Dir())
	testfixture.NoStagingLeft(t, remoteDir)
	enginetest.ExpectContentFree(t, result, err, files["one.bin"], root.Dir())
}

func TestLinuxDirDownloadRoundTrip(t *testing.T) {
	ctx := context.Background()
	engine := enginetest.TestEngine(t, transferremote.New(shStreamRunner(), "t", transfercore.DefaultLimits()), transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	remoteDir := t.TempDir()

	files, dirs := linuxTreeSpec()
	// Seed the remote tree directly on disk: the temp directory plays the
	// remote host.
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(remoteDir, "src", filepath.FromSlash(dir)), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	for name, data := range files {
		path := filepath.Join(remoteDir, "src", filepath.FromSlash(name))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// Mirror the same spec locally as the expected tree.
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(root.Dir(), "expected", filepath.FromSlash(dir)), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	for name, data := range files {
		testfixture.WriteLocalFile(t, root, "expected/"+name, data)
	}

	result, err := engine.Download(ctx, root, filepath.ToSlash(filepath.Join(remoteDir, "src")), "out", false, nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	want := linuxWantDirResult(t, root, "expected")
	if result != want {
		t.Fatalf("download result = %+v, want %+v", result, want)
	}
	linuxVerifyTree(t, filepath.Join(root.Dir(), "out"), dirs, files)

	testfixture.NoStagingLeft(t, root.Dir())
	testfixture.NoStagingLeft(t, remoteDir)
	info, err := os.Stat(filepath.Join(root.Dir(), "out", "empty"))
	if err != nil {
		t.Fatalf("stat out/empty: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("out/empty is not a directory")
	}
}
