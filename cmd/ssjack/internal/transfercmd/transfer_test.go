package transfercmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestPrepareTransferAcceptsRoots(t *testing.T) {
	dir := realTempDir(t)
	vault := filepath.Join(realTempDir(t), "v.ktav")
	subA, subB := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, sub := range []string{subA, subB} {
		if err := os.MkdirAll(sub, 0700); err != nil {
			t.Fatal(err)
		}
	}
	defaults := transfercore.DefaultLimits()
	options, err := Prepare(vault, []string{subA, "named=" + subB}, defaults.MaxBytes, defaults.MaxEntries)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(options.Roots) != 2 || options.Roots[0].Name() != "" || options.Roots[1].Name() != "named" {
		t.Fatalf("unexpected roots: %q %q", options.Roots[0].Name(), options.Roots[1].Name())
	}
	if options.Limits.MaxBytes != defaults.MaxBytes {
		t.Fatalf("limits.MaxBytes = %d, want %d", options.Limits.MaxBytes, defaults.MaxBytes)
	}
	empty, err := Prepare(vault, nil, defaults.MaxBytes, defaults.MaxEntries)
	if err != nil || len(empty.Roots) != 0 || empty.Limits.Validate() != nil {
		t.Fatalf("no-spec Prepare: roots=%d limits=%v err=%v", len(empty.Roots), empty.Limits, err)
	}
}

func TestPrepareTransferRejectsDuplicateNames(t *testing.T) {
	dir := realTempDir(t)
	vault := filepath.Join(realTempDir(t), "v.ktav")
	subA, subB := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, sub := range []string{subA, subB} {
		if err := os.MkdirAll(sub, 0700); err != nil {
			t.Fatal(err)
		}
	}
	defaults := transfercore.DefaultLimits()
	for _, specs := range [][]string{
		{"dup=" + subA, "dup=" + subB},
		{subA, subB},
	} {
		if _, err := Prepare(vault, specs, defaults.MaxBytes, defaults.MaxEntries); err == nil || !strings.Contains(err.Error(), "duplicate transfer root name") {
			t.Fatalf("duplicate names accepted: %q => %v", specs, err)
		}
	}
}

func TestPrepareTransferRejectsVaultInsideRoot(t *testing.T) {
	subA := filepath.Join(realTempDir(t), "a")
	if err := os.MkdirAll(subA, 0700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(subA, "v.ktav")
	defaults := transfercore.DefaultLimits()
	if _, err := Prepare(vault, []string{subA}, defaults.MaxBytes, defaults.MaxEntries); err == nil || !strings.Contains(err.Error(), "must not contain the vault") {
		t.Fatalf("vault inside root accepted: %v", err)
	}
}

func TestPrepareTransferValidatesLimits(t *testing.T) {
	subA := filepath.Join(realTempDir(t), "a")
	if err := os.MkdirAll(subA, 0700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(realTempDir(t), "v.ktav")
	defaults := transfercore.DefaultLimits()
	for _, tc := range []struct {
		name       string
		maxBytes   int64
		maxEntries int
	}{
		{"zero bytes", 0, defaults.MaxEntries},
		{"zero entries", defaults.MaxBytes, 0},
		{"negative entries", defaults.MaxBytes, -5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Prepare(vault, []string{subA}, tc.maxBytes, tc.maxEntries); err == nil || !strings.Contains(err.Error(), "transfer limits are invalid") {
				t.Fatalf("invalid limits accepted: %d %d => %v", tc.maxBytes, tc.maxEntries, err)
			}
		})
	}
}

// realTempDir returns a temp directory with symlinks resolved; transfer roots
// refuse symlinked ancestors such as macOS /var.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
