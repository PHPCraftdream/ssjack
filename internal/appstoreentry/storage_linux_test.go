//go:build linux

package appstoreentry

import (
	"bytes"
	"crypto/sha256"

	"os"
	"path/filepath"
	"testing"
)

func privateDir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRequireUninstalled(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		s, err := Open(privateDir(t))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.RequireUninstalled(); err != nil {
			t.Fatalf("absent binding rejected: %v", err)
		}
	})
	for _, tc := range []struct {
		name  string
		setup func(string) error
	}{
		{"symlink", func(path string) error { return os.Symlink("missing-target", path) }},
		{"permissive", func(path string) error { return os.WriteFile(path, []byte("partial"), 0644) }},
		{"partial", func(path string) error { return os.WriteFile(path, []byte("partial"), 0600) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := privateDir(t)
			if err := tc.setup(filepath.Join(p, bindingName)); err != nil {
				t.Fatal(err)
			}
			s, err := Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.RequireUninstalled(); err == nil {
				t.Fatal("existing binding accepted")
			}
		})
	}
}

func TestInstallLoadVerify(t *testing.T) {
	p := privateDir(t)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ciphertext := []byte{0, 0xff, 0x91, 0x22, 0x00, 0x7e}
	if err := s.Install(ciphertext); err != nil {
		t.Fatal(err)
	}
	got, hash, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ciphertext) || hash != sha256.Sum256(ciphertext) {
		t.Fatal("loaded bytes or digest differ")
	}
	if err := s.VerifyUnchanged(hash); err != nil {
		t.Fatal(err)
	}
}

func TestInstallRefusesExistingBindingWithoutChangingIt(t *testing.T) {
	p := privateDir(t)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, second := []byte("synthetic ciphertext one"), []byte("different ciphertext")
	if err := s.Install(first); err != nil {
		t.Fatal(err)
	}
	if err := s.Install(second); err == nil {
		t.Fatal("second install succeeded")
	}
	got, err := os.ReadFile(filepath.Join(p, bindingName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("binding changed: %q", got)
	}
}

func TestOpenExclusivelyLocksDirectory(t *testing.T) {
	p := privateDir(t)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if other, err := Open(p); err == nil {
		other.Close()
		t.Fatal("second Open acquired lock")
	}
}

func TestVerifyDetectsSameBytesAtNewInode(t *testing.T) {
	p := privateDir(t)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	data := []byte("same ciphertext")
	if err := s.Install(data); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	name := filepath.Join(p, bindingName)
	replacement := filepath.Join(p, "replacement")
	if err := os.WriteFile(replacement, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, name); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyUnchanged(h); err == nil {
		t.Fatal("replacement inode accepted")
	}
}

func TestLoadRejectsChangedPermissions(t *testing.T) {
	p := privateDir(t)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Install([]byte("secret ciphertext")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(p, bindingName), 0640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); err == nil {
		t.Fatal("permissive binding accepted")
	}
}

func TestOpenRejectsSymlinksAndWritableAncestors(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("directory symlink accepted")
	}
	bindingLink := filepath.Join(real, bindingName)
	if err := os.Symlink(filepath.Join(parent, "absent"), bindingLink); err != nil {
		t.Fatal(err)
	}
	s, err := Open(real)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); err == nil {
		t.Fatal("binding symlink accepted")
	}
	s.Close()

	unsafe := filepath.Join(parent, "unsafe")
	if err := os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(unsafe, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(child); err == nil {
		t.Fatal("group/world-writable ancestor accepted")
	}
}

func TestOpenRejectsNoFollowAncestorSymlink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(target, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(nested, "store")
	if err := os.Mkdir(storePath, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(link, "nested", "store")); err == nil {
		t.Fatal("ancestor symlink accepted")
	}

	permissive := filepath.Join(parent, "permissive")
	if err := os.Mkdir(permissive, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(permissive, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(permissive); err == nil {
		t.Fatal("final directory with permissive permissions accepted")
	}
}
