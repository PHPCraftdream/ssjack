//go:build windows

package pathsafe_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/osfs"
)

func TestParseRootRefusesFilesystemRootWindows(t *testing.T) {
	_, err := ParseRoot(`C:\`, "")
	requireClass(t, err, transfercore.ClassRefusedPath)
	// filepath.Clean normalizes C:\. to C:\, so it must also be refused.
	_, err = ParseRoot(`C:\.`, "")
	requireClass(t, err, transfercore.ClassRefusedPath)
}

func TestReparsePointRefusedWindows(t *testing.T) {
	root, dir := testRoot(t)
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatalf("create real dir: %v", err)
	}
	target, err := windows.UTF16PtrFromString(real)
	if err != nil {
		t.Fatalf("UTF16PtrFromString(real): %v", err)
	}
	linkPath := filepath.Join(dir, "link")
	link, err := windows.UTF16PtrFromString(linkPath)
	if err != nil {
		t.Fatalf("UTF16PtrFromString(link): %v", err)
	}
	// SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
	// the unprivileged-create flag (0x2, MS docs) is absent from x/sys v0.46.0.
	flags := uint32(windows.SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2)
	if err := windows.CreateSymbolicLink(link, target, flags); err != nil {
		t.Fatalf("CreateSymbolicLink: %v", err)
	}
	defer os.Remove(linkPath)
	inside := filepath.Join(real, "inside.txt")
	writeFile(t, inside, []byte("inside"))

	_, err = ParseRoot(linkPath, "")
	requireClass(t, err, transfercore.ClassRefusedPath, dir)

	info, err := osfs.StatPath(linkPath)
	if err != nil {
		t.Fatalf("osfs.StatPath(link): %v", err)
	}
	if !info.Reparse || !info.Exist {
		t.Fatalf("osfs.StatPath(link) = %+v, want reparse:true exist:true", info)
	}

	_, err = root.WalkSource("link", transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	_, err = root.WalkSource("link/inside.txt", transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	if _, _, err := root.OpenSourceFile("link/inside.txt"); err == nil {
		t.Fatal("OpenSourceFile(link/inside.txt) = nil error, want refused")
	} else {
		requireClass(t, err, transfercore.ClassRefusedPath, dir)
	}

	_, err = NewStaging(filepath.Join("link", "dest.txt"), root.Dir(), false)
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	_, err = NewStaging("dest.txt", linkPath, false)
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
}

func TestReservedNameDestinationWindows(t *testing.T) {
	_, dir := testRoot(t)
	for _, name := range []string{"CON", "x.", "a:b"} {
		_, err := NewStaging(name, dir, false)
		if err == nil {
			t.Fatalf("NewStaging(%q) = nil error, want refused", name)
		}
		requireClass(t, err, transfercore.ClassRefusedPath, dir)
	}
}
