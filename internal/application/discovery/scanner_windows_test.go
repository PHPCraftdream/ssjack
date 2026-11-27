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
		target := filepath.Join(root, "real")
		writeDescriptor(t, target, "real")
		link := filepath.Join(root, "symlink")
		if err := windows.CreateSymbolicLink(windows.StringToUTF16Ptr(link), windows.StringToUTF16Ptr(target), windows.SYMBOLIC_LINK_FLAG_DIRECTORY); err != nil {
			t.Skip("directory reparse fixture unavailable")
		}
		if _, err := os.Lstat(link); err != nil {
			t.Skip("directory reparse fixture unavailable after creation")
		}

		got := Scan(root)
		if len(got.Candidates) != 1 || got.Candidates[0].Path != "real" {
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

func TestScanRootJunctionResolved(t *testing.T) {
	t.Run("junction root is resolved and scanned", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "ordinary")
		writeDescriptor(t, target, "realroot")
		junction := filepath.Join(parent, "junctionroot")
		if err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).Run(); err != nil {
			t.Skip("directory junction fixture unavailable")
		}
		got := Scan(junction)
		if hasReason(got, "root_unsafe") || len(got.Candidates) != 1 || got.Candidates[0].Path != "." {
			t.Fatalf("candidate_count=%d root_unsafe=%t", len(got.Candidates), hasReason(got, "root_unsafe"))
		}
		requireResolvedTo(t, got.Candidates[0].CanonicalPath, target)
	})
}

func TestDescriptorHashRejectsJunction(t *testing.T) {
	t.Run("junction is not canonical", func(t *testing.T) {
		parent := canonicalTemp(t)
		target := filepath.Join(parent, "ordinary")
		writeDescriptor(t, target, "realroot")
		junction := filepath.Join(parent, "junctionroot")
		if err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).Run(); err != nil {
			t.Skip("directory junction fixture unavailable")
		}
		if _, err := DescriptorHash(junction); err == nil || err.Error() != "path_not_canonical" {
			t.Fatalf("reason=%v want=path_not_canonical", err)
		}
	})
}

func TestScanRejectsDirectoryJunction(t *testing.T) {
	t.Run("directory junction", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "real")
		writeDescriptor(t, target, "real")
		junction := filepath.Join(root, "junction")
		if err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).Run(); err != nil {
			t.Skip("directory junction fixture unavailable")
		}

		got := Scan(root)
		if len(got.Candidates) != 1 || got.Candidates[0].Path != "real" {
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

func TestTrimExtendedPrefix(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"drive":     {`\\?\C:\Users\runner\app`, `C:\Users\runner\app`},
		"unc":       {`\\?\UNC\server\share\app`, `\\server\share\app`},
		"plain":     {`C:\Users\runner\app`, `C:\Users\runner\app`},
		"plain unc": {`\\server\share\app`, `\\server\share\app`},
	} {
		t.Run(name, func(t *testing.T) {
			if got := trimExtendedPrefix(tc.in); got != tc.want {
				t.Fatalf("trimExtendedPrefix(%q)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestResolveRootHasNoExtendedPrefix(t *testing.T) {
	resolved, err := resolveRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) >= 4 && resolved[:4] == `\\?\` {
		t.Fatalf("resolved root keeps the extended prefix: %q", resolved)
	}
	if !filepath.IsAbs(resolved) {
		t.Fatalf("resolved root is not absolute: %q", resolved)
	}
}
