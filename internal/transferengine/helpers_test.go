package transferengine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

func testEngine(t *testing.T, remote transferremote.Remote, limits transfercore.Limits) *Engine {
	t.Helper()
	engine, err := New(remote, limits)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return engine
}

// testRoot returns a Root on a symlink-free temp directory (EvalSymlinks
// because ParseRoot refuses symlinked ancestors, which t.TempDir has on
// darwin).
func testRoot(t *testing.T) *transferlocal.Root {
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

// writeLocalFile creates parent directories and writes content under the root.
func writeLocalFile(t *testing.T, root *transferlocal.Root, rel string, content []byte) string {
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

// binaryContent returns n bytes of deterministic binary data covering the
// full byte range.
func binaryContent(n int) []byte {
	content := make([]byte, n)
	for i := range content {
		content[i] = byte(i * 7 % 251)
	}
	return content
}

func expectClass(t *testing.T, err error, want transfercore.Class) {
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

// expectNoResult fails when a failed transfer returned a populated result.
func expectNoResult(t *testing.T, result Result) {
	t.Helper()
	if result != (Result{}) {
		t.Fatalf("failure returned a non-zero result: %+v", result)
	}
}

// expectCalls asserts the exact sequence of recorded remote calls.
func expectCalls(t *testing.T, fake *fakeRemote, want []string) {
	t.Helper()
	got := fake.callsSnapshot()
	if len(got) != len(want) {
		t.Fatalf("remote calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("remote calls = %v, want %v", got, want)
		}
	}
}

// expectPhases asserts the progress stream: each of the five phases appears
// in order (repeats collapse), and the last report is cleanup with the total
// bytes.
func expectPhases(t *testing.T, got []Progress, total int64) {
	t.Helper()
	want := []string{
		transfercore.PhasePreflight,
		transfercore.PhaseTransfer,
		transfercore.PhaseVerify,
		transfercore.PhasePublish,
		transfercore.PhaseCleanup,
	}
	if len(got) == 0 {
		t.Fatal("no progress reports")
	}
	var names []string
	for _, p := range got {
		if len(names) == 0 || names[len(names)-1] != p.Phase {
			names = append(names, p.Phase)
		}
	}
	if len(names) != len(want) {
		t.Fatalf("phases = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("phases = %v, want %v", names, want)
		}
	}
	last := got[len(got)-1]
	if last.Phase != transfercore.PhaseCleanup || last.Bytes != total {
		t.Fatalf("last progress = %+v, want cleanup with %d bytes", last, total)
	}
}

// noStagingLeft fails if any job-owned staging directory remains in dir.
func noStagingLeft(t *testing.T, dir string) {
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

// expectContentFree fails when a result or an error message carries file
// content or a filesystem path.
func expectContentFree(t *testing.T, result Result, err error, content []byte, secretPath string) {
	t.Helper()
	for _, repr := range []string{fmt.Sprintf("%+v", result), errorText(err)} {
		if strings.Contains(repr, secretPath) {
			t.Fatalf("transfer outcome contains the local path: %s", repr)
		}
		if content != nil && len(content) > 0 && strings.Contains(repr, string(content)) {
			t.Fatalf("transfer outcome contains file content: %s", repr)
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
