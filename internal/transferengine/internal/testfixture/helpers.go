package testfixture

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// TestRoot returns a Root on a symlink-free temp directory (EvalSymlinks
// because ParseRoot refuses symlinked ancestors, which t.TempDir has on
// darwin).
func TestRoot(t *testing.T) *transferlocal.Root {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := transferlocal.ParseRoot(dir, "")
	if err != nil {
		t.Fatalf("ParseRoot: %v", err)
	}
	return root
}

// WriteLocalFile creates parent directories and writes content under the root.
func WriteLocalFile(t *testing.T, root *transferlocal.Root, rel string, content []byte) string {
	t.Helper()
	path := filepath.Join(root.Dir(), filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// BinaryContent returns n bytes of deterministic binary data covering the
// full byte range.
func BinaryContent(n int) []byte {
	content := make([]byte, n)
	for i := range content {
		content[i] = byte(i * 7 % 251)
	}
	return content
}

func ExpectClass(t *testing.T, err error, want transfercore.Class) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected class %q, got nil", want)
	}
	var e *transfercore.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *transfercore.Error, got %T: %v", err, err)
	}
	if e.Class != want {
		t.Fatalf("expected class %q, got %q (%s)", want, e.Class, e.Message)
	}
}

// ExpectCalls asserts the exact sequence of recorded remote calls.
func ExpectCalls(t *testing.T, fake *FakeRemote, want []string) {
	t.Helper()
	got := fake.CallsSnapshot()
	if len(got) != len(want) {
		t.Fatalf("remote calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("remote calls = %v, want %v", got, want)
		}
	}
}

// NoStagingLeft fails if any job-owned staging directory remains in dir.
func NoStagingLeft(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".ssjack-transfer-") {
			t.Fatalf("staging directory left behind: %s", entry.Name())
		}
	}
}

func ErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
