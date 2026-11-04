//go:build darwin || windows

package appstoreentry

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func nativeStorePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store")
	root, err := ownerfs.MakeRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestNativeInstallationBindingRoundtripExclusiveOwnerAndChangeDetection(t *testing.T) {
	path := nativeStorePath(t)
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if !Supported() {
		t.Fatal("native protected store is not supported")
	}
	if second, err := Open(path); err == nil {
		second.Close()
		t.Fatal("second installation owner acquired the store")
	}
	if err := store.RequireUninstalled(); err != nil {
		t.Fatal(err)
	}
	encoded := []byte("synthetic encrypted installation bytes")
	if err := store.Install(encoded); err != nil {
		t.Fatal(err)
	}
	if err := store.Install([]byte("replacement")); err == nil {
		t.Fatal("native installation was overwritten")
	}
	if err := store.RequireUninstalled(); err == nil {
		t.Fatal("installed binding was called absent")
	}
	loaded, digest, err := store.Load()
	if err != nil || !bytes.Equal(loaded, encoded) || digest != sha256.Sum256(encoded) {
		t.Fatal("native encrypted installation roundtrip changed bytes")
	}
	if err := store.VerifyUnchanged(digest); err != nil {
		t.Fatal(err)
	}
	dev, ino, err := store.Identity()
	if err != nil || dev == 0 || ino == 0 {
		t.Fatal("native protected installation identity is unavailable")
	}
	file, err := store.Root()
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := ownerfs.Adopt(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer adopted.Close()
	actualDev, actualIno, err := adopted.Identity()
	if err != nil || dev != actualDev || ino != actualIno {
		t.Fatal("native root export changed physical identity")
	}
	edit, err := adopted.Write(bindingName, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := edit.WriteAt([]byte{0xff}, 0); err != nil {
		edit.Close()
		t.Fatal(err)
	}
	edit.Sync()
	edit.Close()
	if err := store.VerifyUnchanged(digest); err == nil {
		t.Fatal("changed binding was adopted as the checked installation")
	}
}

func TestNativeInstallationRefusesUnprotectedAndReplacedRoot(t *testing.T) {
	unprotected := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(unprotected, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if root, err := Open(unprotected); err == nil {
		root.Close()
		t.Fatal("unprotected native directory was accepted")
	}
	path := nativeStorePath(t)
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	moved := path + "-old"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	root, err := ownerfs.MakeRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	if _, _, err := store.Identity(); err == nil {
		t.Fatal("replacement root retained the old installation identity")
	}
}
