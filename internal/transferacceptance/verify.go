//go:build linux || darwin

package transferacceptance

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// SeedPayload returns deterministic pseudo-random bytes with binary corner
// values, so repeated trees and hashes are reproducible.
func SeedPayload(size int, seed byte) []byte {
	data := make([]byte, size)
	state := uint32(seed)*2654435761 + 1
	for i := range data {
		state = state*1664525 + 1013904223
		data[i] = byte(state >> 24)
	}
	if size >= 8 {
		copy(data[:8], []byte{0x00, 0x01, 0xff, 0xfe, 0x7f, 0x80, 0x0a, 0x0d})
	}
	return data
}

// WriteTree creates directories and regular files under base; keys are
// slash-separated relative paths.
func WriteTree(t *testing.T, base string, files map[string][]byte, dirs []string) {
	t.Helper()
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(base, filepath.FromSlash(dir)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range files {
		path := filepath.Join(base, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// CompareTrees compares two directory trees byte-exactly: same regular
// files, same bytes, same directory set, nothing else.
func CompareTrees(t *testing.T, want, got string) {
	t.Helper()
	wantFiles, wantDirs := treeState(t, want)
	gotFiles, gotDirs := treeState(t, got)
	if len(wantFiles) != len(gotFiles) || len(wantDirs) != len(gotDirs) {
		t.Fatalf("tree shape differs: %d files/%d dirs vs %d files/%d dirs", len(wantFiles), len(wantDirs), len(gotFiles), len(gotDirs))
	}
	for name, data := range wantFiles {
		other, ok := gotFiles[name]
		if !ok || !bytes.Equal(data, other) {
			t.Fatalf("tree content differs at %q", name)
		}
	}
	sort.Strings(wantDirs)
	sort.Strings(gotDirs)
	for i := range wantDirs {
		if wantDirs[i] != gotDirs[i] {
			t.Fatalf("directory sets differ: %v vs %v", wantDirs, gotDirs)
		}
	}
}

// AssertNoStaging fails when a transfer staging directory remains in base.
func AssertNoStaging(t *testing.T, base string) {
	t.Helper()
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".ssjack-transfer-") {
			t.Fatalf("staging directory %q was left behind in %s", entry.Name(), base)
		}
	}
}

// treeState maps every regular file to its bytes and lists all directories.
func treeState(t *testing.T, base string) (map[string][]byte, []string) {
	t.Helper()
	files := make(map[string][]byte)
	var dirs []string
	err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			dirs = append(dirs, rel)
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected non-regular entry %q", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files, dirs
}

// assertTreeSnapshot requires a fixture tree to retain the same files, bytes,
// and directories as a previously captured state.
func assertTreeSnapshot(t *testing.T, base string, wantFiles map[string][]byte, wantDirs []string) {
	t.Helper()
	gotFiles, gotDirs := treeState(t, base)
	if len(gotFiles) != len(wantFiles) || len(gotDirs) != len(wantDirs) {
		t.Fatalf("fixture tree %s changed shape: got %d files/%d dirs, want %d files/%d dirs", filepath.Base(base), len(gotFiles), len(gotDirs), len(wantFiles), len(wantDirs))
	}
	for name, want := range wantFiles {
		got, ok := gotFiles[name]
		if !ok || !bytes.Equal(got, want) {
			t.Fatalf("fixture file %q changed", name)
		}
	}
	sort.Strings(gotDirs)
	sort.Strings(wantDirs)
	for i := range wantDirs {
		if gotDirs[i] != wantDirs[i] {
			t.Fatalf("fixture directories changed: got %v, want %v", gotDirs, wantDirs)
		}
	}
}
