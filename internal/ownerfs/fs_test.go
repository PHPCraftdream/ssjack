package ownerfs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rootFixture(t *testing.T) (*Root, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store")
	root, err := MakeRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, path
}
func writeFixture(t *testing.T, root *Root, name string, data []byte) {
	t.Helper()
	file, err := root.Write(name, true)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := file.Write(data); err != nil || n != len(data) {
		file.Close()
		t.Fatal("native ciphertext write failed")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Flush(name); err != nil {
		t.Fatal(err)
	}
}
func readFixture(t *testing.T, root *Root, name string) []byte {
	t.Helper()
	file, err := root.Read(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		t.Fatal("native ciphertext read failed")
	}
	return data
}

func TestNativeProtectedRootIdentityLockAndExclusivePublication(t *testing.T) {
	root, path := rootFixture(t)
	dev, ino, err := root.Identity()
	if err != nil || dev == 0 || ino == 0 {
		t.Fatal("native root identity is unavailable")
	}
	file, err := root.File()
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := Adopt(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer adopted.Close()
	otherDev, otherIno, err := adopted.Identity()
	if err != nil || dev != otherDev || ino != otherIno {
		t.Fatal("adoption changed the protected root identity")
	}
	unlock, err := root.Lock()
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if release, err := other.Lock(); !errors.Is(err, ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("second writer acquired a native root lock")
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if err := unlock(); err != nil {
		t.Fatal("lock release is not idempotent")
	}
	candidates, err := root.Child("candidates", true)
	if err != nil {
		t.Fatal(err)
	}
	defer candidates.Close()
	snapshots, err := root.Child("snapshots", true)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshots.Close()
	first, second := []byte("synthetic first ciphertext"), []byte("synthetic replacement ciphertext")
	writeFixture(t, candidates, "one.bin", first)
	if err := candidates.Rename("one.bin", snapshots, "one.bin", false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFixture(t, snapshots, "one.bin"), first) {
		t.Fatal("exclusive publication changed ciphertext")
	}
	writeFixture(t, candidates, "one.bin", second)
	if err := candidates.Rename("one.bin", snapshots, "one.bin", false); !errors.Is(err, ErrExists) {
		t.Fatal("native exclusive publication overwrote the destination")
	}
	if !bytes.Equal(readFixture(t, snapshots, "one.bin"), first) || !bytes.Equal(readFixture(t, candidates, "one.bin"), second) {
		t.Fatal("refused publication changed source/destination")
	}
	if err := candidates.Rename("one.bin", snapshots, "one.bin", true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFixture(t, snapshots, "one.bin"), second) {
		t.Fatal("explicit replacement failed")
	}
}

func TestNativeAnonymousSpoolHasNoNameBeforeUse(t *testing.T) {
	root, path := rootFixture(t)
	file, err := root.Temporary()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	metadata, err := Stat(file, true)
	if err != nil || metadata.Links != 0 || metadata.Size != 0 || metadata.Directory {
		t.Fatal("native spool is not an owned anonymous empty file")
	}
	assertSpoolUnreachable(t, path)
	if err := root.Entries(func(name string) error {
		if strings.HasPrefix(name, ".spool-") {
			return ErrInvalid
		}
		return nil
	}); err != nil {
		t.Fatal("temporary spool retained a visible name")
	}
	value := []byte("synthetic anonymous ciphertext")
	if _, err := file.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	metadata, err = Stat(file, true)
	if err != nil || metadata.Size != int64(len(value)) {
		t.Fatal("native spool lost its data or anonymity")
	}
	assertSpoolUnreachable(t, path)
}

func assertSpoolUnreachable(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".spool-") {
			continue
		}
		file, err := os.Open(filepath.Join(path, entry.Name()))
		if err == nil {
			file.Close()
			t.Fatal("anonymous ciphertext is reachable through a filesystem name")
		}
		if !os.IsNotExist(err) && !os.IsPermission(err) && !errors.Is(mapError(err), ErrMissing) {
			t.Fatalf("unexpected unlinked spool lookup result: %v", err)
		}
	}
}

func TestNativeRootRefusesTraversalHardLinksAndUnexpectedPermissions(t *testing.T) {
	root, path := rootFixture(t)
	for _, name := range []string{"", ".", "..", "../escape", `..\escape`, "stream:secret", "a/b", "a\x00b"} {
		if file, err := root.Write(name, true); !errors.Is(err, ErrInvalid) {
			if file != nil {
				file.Close()
			}
			t.Fatal("invalid native name reached the filesystem")
		}
		if child, err := root.Child(name, true); !errors.Is(err, ErrInvalid) {
			if child != nil {
				child.Close()
			}
			t.Fatal("invalid directory name escaped its root")
		}
	}
	writeFixture(t, root, "original.bin", []byte("synthetic ciphertext"))
	if err := os.Link(filepath.Join(path, "original.bin"), filepath.Join(path, "alias.bin")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"original.bin", "alias.bin"} {
		if file, err := root.Read(name); err == nil {
			file.Close()
			t.Fatal("hard-linked ciphertext was accepted")
		}
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if file, err := root.Read("original.bin"); !errors.Is(err, ErrUnavailable) {
		if file != nil {
			file.Close()
		}
		t.Fatal("closed native root remained usable")
	}
}
