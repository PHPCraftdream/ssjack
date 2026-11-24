//go:build windows

package discovery

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestScanRejectsDirectoryReparseSymlink(t *testing.T) {
	t.Run("directory symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		writeDescriptor(t, target, "target")
		link := filepath.Join(root, "symlink")
		if err := windows.CreateSymbolicLink(windows.StringToUTF16Ptr(link), windows.StringToUTF16Ptr(target), windows.SYMBOLIC_LINK_FLAG_DIRECTORY); err != nil {
			t.Skip("directory reparse fixture unavailable")
		}
		if _, err := os.Lstat(link); err != nil {
			t.Skip("directory reparse fixture unavailable after creation")
		}

		got := Scan(root)
		if len(got.Candidates) != 1 || got.Candidates[0].Path != "target" {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
		found := false
		for _, diagnostic := range got.Diagnostics {
			if diagnostic.Path == "symlink" && diagnostic.Reason == "entry_unsafe" {
				found = true
			}
		}
		if !found {
			t.Fatal("missing entry_unsafe diagnostic for directory symlink")
		}
	})
}

func TestScanRejectsDirectoryJunction(t *testing.T) {
	t.Run("directory junction", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		writeDescriptor(t, target, "target")
		junction := filepath.Join(root, "junction")
		if err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).Run(); err != nil {
			t.Skip("directory junction fixture unavailable")
		}

		got := Scan(root)
		if len(got.Candidates) != 1 || got.Candidates[0].Path != "target" {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
		found := false
		for _, diagnostic := range got.Diagnostics {
			if diagnostic.Path == "junction" && diagnostic.Reason == "entry_unsafe" {
				found = true
			}
		}
		if !found {
			t.Fatal("missing entry_unsafe diagnostic for junction")
		}
	})
}
