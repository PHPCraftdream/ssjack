package transferlocal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRootSpecForms(t *testing.T) {
	root, dir := testRoot(t)
	if root.Name() != "" {
		t.Fatalf("anonymous root name: %q", root.Name())
	}
	if root.Dir() != filepath.Clean(dir) {
		t.Fatalf("root dir: %q", root.Dir())
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	named, err := ParseRoot("NAME="+sub, "")
	if err != nil {
		t.Fatal(err)
	}
	if named.Name() != "NAME" {
		t.Fatalf("named root: %q", named.Name())
	}
	if named.Dir() != filepath.Clean(sub) {
		t.Fatalf("named root dir: %q", named.Dir())
	}
	plain, err := ParseRoot(sub, "")
	if err != nil {
		t.Fatal(err)
	}
	if plain.Name() != "" {
		t.Fatalf("plain root name: %q", plain.Name())
	}
}

func TestParseRootNameValidation(t *testing.T) {
	_, dir := testRoot(t)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	for _, name := range []string{"", "bad name", strings.Repeat("a", 65)} {
		if _, err := ParseRoot(name+"="+sub, ""); err == nil {
			t.Fatalf("name %q accepted", name)
		} else {
			requireClass(t, err, "refused_path", dir)
		}
	}
	good, err := ParseRoot(strings.Repeat("a", 64)+"="+sub, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(good.Name()) != 64 {
		t.Fatalf("64-byte name rejected: %q", good.Name())
	}
}

func TestParseRootRefusals(t *testing.T) {
	_, dir := testRoot(t)
	missing := filepath.Join(dir, "missing")
	_, err := ParseRoot(missing, "")
	requireClass(t, err, "refused_path", dir)
	file := filepath.Join(dir, "file.txt")
	writeFile(t, file, []byte("data"))
	_, err = ParseRoot(file, "")
	requireClass(t, err, "refused_path", dir)
}

func TestParseRootVaultExclusion(t *testing.T) {
	_, dir := testRoot(t)
	sibling, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		vault string
		ok    bool
	}{
		{"file inside root", filepath.Join(dir, "vault.ssjack"), false},
		{"equal to root", dir, false},
		{"nested inside root", filepath.Join(dir, "nested", "vault.ssjack"), false},
		{"sibling dir", sibling, true},
		{"sibling file", filepath.Join(sibling, "f"), true},
		{"empty", "", true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseRoot(dir, c.vault)
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			requireClass(t, err, "refused_path", dir, sibling)
		})
	}
	_, err = ParseRoot(dir, "vault.ssjack")
	requireClass(t, err, "refused_path", dir)
}

func TestRootsSelectEmpty(t *testing.T) {
	_, err := NewRoots().Select("")
	requireClass(t, err, "refused_path")
}

func TestRootsAddNil(t *testing.T) {
	err := NewRoots().Add(nil)
	requireClass(t, err, "refused_path")
}

func TestRootsDuplicateNames(t *testing.T) {
	_, dir := testRoot(t)
	rs := NewRoots()
	first, err := ParseRoot("one="+dir, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseRoot("one="+dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Add(first); err != nil {
		t.Fatal(err)
	}
	err = rs.Add(second)
	requireClass(t, err, "refused_path", dir)
}

func TestRootsAnonymousCollision(t *testing.T) {
	_, dir := testRoot(t)
	rs := NewRoots()
	first, err := ParseRoot(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseRoot(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Add(first); err != nil {
		t.Fatal(err)
	}
	err = rs.Add(second)
	requireClass(t, err, "refused_path", dir)
}

func TestRootsSelectAnonymousSingle(t *testing.T) {
	_, dir := testRoot(t)
	rs := NewRoots()
	only, err := ParseRoot(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Add(only); err != nil {
		t.Fatal(err)
	}
	got, err := rs.Select("")
	if err != nil {
		t.Fatal(err)
	}
	if got != only {
		t.Fatal("select returned a different root")
	}
}

func TestRootsSelectEmptyWithTwoNamed(t *testing.T) {
	_, dir := testRoot(t)
	rs := NewRoots()
	for _, name := range []string{"one", "two"} {
		root, err := ParseRoot(name+"="+dir, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := rs.Add(root); err != nil {
			t.Fatal(err)
		}
	}
	_, err := rs.Select("")
	requireClass(t, err, "refused_path", dir)
}

func TestRootsSelectKnownAndUnknown(t *testing.T) {
	_, dir := testRoot(t)
	rs := NewRoots()
	root, err := ParseRoot("known="+dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Add(root); err != nil {
		t.Fatal(err)
	}
	got, err := rs.Select("known")
	if err != nil || got != root {
		t.Fatalf("select known: %v", err)
	}
	_, err = rs.Select("unknown")
	requireClass(t, err, "refused_path", dir)
}
