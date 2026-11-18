// Package enginetest holds the test helpers that depend on the public
// internal/transferengine API (its constructors and result/progress types).
// Keeping them separate from internal/transferengine/internal/testfixture
// lets the whitebox transferengine test package consume testfixture without
// an import cycle, while external test packages can use both.
package enginetest

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// TestEngine builds an Engine or fails the test.
func TestEngine(t *testing.T, remote transferremote.Remote, limits transfercore.Limits) *transferengine.Engine {
	t.Helper()
	engine, err := transferengine.New(remote, limits)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return engine
}

// ExpectNoResult fails when a failed transfer returned a populated result.
func ExpectNoResult(t *testing.T, result transferengine.Result) {
	t.Helper()
	if result != (transferengine.Result{}) {
		t.Fatalf("failure returned a non-zero result: %+v", result)
	}
}

// ExpectPhases asserts the progress stream: each of the five phases appears
// in order (repeats collapse), and the last report is cleanup with the total
// bytes.
func ExpectPhases(t *testing.T, got []transferengine.Progress, total int64) {
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

// ExpectContentFree fails when a result or an error message carries file
// content or a filesystem path.
func ExpectContentFree(t *testing.T, result transferengine.Result, err error, content []byte, secretPath string) {
	t.Helper()
	for _, repr := range []string{fmt.Sprintf("%+v", result), ErrorText(err)} {
		if strings.Contains(repr, secretPath) {
			t.Fatalf("transfer outcome contains the local path: %s", repr)
		}
		if content != nil && len(content) > 0 && strings.Contains(repr, string(content)) {
			t.Fatalf("transfer outcome contains file content: %s", repr)
		}
	}
}

func ErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

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
