package approval

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func validRecord(t *testing.T, name string) Record {
	t.Helper()
	return Record{Name: name, Path: filepath.Join(t.TempDir(), name), Hash: strings.Repeat("ab", 32)}
}

func TestValidateName(t *testing.T) {
	t.Run("valid dash name", func(t *testing.T) { validateNameCase(t, "web-app", true) })
	t.Run("single letter", func(t *testing.T) { validateNameCase(t, "a", true) })
	t.Run("empty name", func(t *testing.T) { validateNameCase(t, "", false) })
	t.Run("leading dash", func(t *testing.T) { validateNameCase(t, "-x", false) })
	t.Run("uppercase", func(t *testing.T) { validateNameCase(t, "X", false) })
	t.Run("space in name", func(t *testing.T) { validateNameCase(t, "a b", false) })
	t.Run("too long", func(t *testing.T) { validateNameCase(t, strings.Repeat("a", 33), false) })
}

func validateNameCase(t *testing.T, name string, want bool) {
	t.Helper()
	if (ValidateName(name) == nil) != want {
		t.Fatalf("ValidateName(%q) mismatch", name)
	}
}

func TestValidatePath(t *testing.T) {
	good := validRecord(t, "tool").Path
	// The oversized path must be absolute on every platform so the case fails
	// only through the length check; only CI exercises the Windows branch.
	absPrefix := "/"
	if runtime.GOOS == "windows" {
		absPrefix = `C:\`
	}
	tooLong := absPrefix + strings.Repeat("a", 512)
	validatePathCase(t, "apps/tool", false)
	validatePathCase(t, good+string(filepath.Separator)+".", false)
	validatePathCase(t, tooLong, false)
	validatePathCase(t, good, true)
}

func validatePathCase(t *testing.T, path string, want bool) {
	t.Helper()
	if (ValidatePath(path) == nil) != want {
		t.Fatalf("ValidatePath(%q) mismatch", path)
	}
}

func TestValidatePathRejectsControlBytes(t *testing.T) {
	t.Run("NUL in path", func(t *testing.T) {
		if err := ValidatePath(filepath.Join(t.TempDir(), "a\x00b")); err == nil {
			t.Fatal("path containing NUL was accepted")
		}
	})
	t.Run("control char in path", func(t *testing.T) {
		if err := ValidatePath(filepath.Join(t.TempDir(), "a\tb")); err == nil {
			t.Fatal("path containing a control character was accepted")
		}
	})
	t.Run("DEL in path", func(t *testing.T) {
		if err := ValidatePath(filepath.Join(t.TempDir(), "a\x7fb")); err == nil {
			t.Fatal("path containing DEL was accepted")
		}
	})
}

func TestValidateHash(t *testing.T) {
	if (ValidateHash(strings.ToUpper(strings.Repeat("ab", 32))) == nil) != false {
		t.Fatal("uppercase hash was accepted")
	}
	if (ValidateHash(strings.Repeat("ab", 31)) == nil) != false {
		t.Fatal("short hash was accepted")
	}
	if (ValidateHash(strings.Repeat("ab", 32)) == nil) != true {
		t.Fatal("valid hash was rejected")
	}
}

func TestValidateRouteSpec(t *testing.T) {
	routeCase(t, "", true)
	routeCase(t, "http://c", false)
	routeCase(t, "docker:c:u", false)
	routeCase(t, "incus:C:u", false)
	routeCase(t, "incus:c:U", false)
	routeCase(t, "incus:c:u ", false)
	routeCase(t, "incus:web-container:alice", true)
}

func routeCase(t *testing.T, spec string, want bool) {
	t.Helper()
	if (ValidateRouteSpec(spec) == nil) != want {
		t.Fatalf("ValidateRouteSpec(%q) mismatch", spec)
	}
}

func TestValidateSet(t *testing.T) {
	t.Run("nil is valid", func(t *testing.T) {
		if err := ValidateSet(nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("too many records", func(t *testing.T) {
		set := make(map[string]Record, MaxApprovals+1)
		for i := 0; i <= MaxApprovals; i++ {
			set[runeName(i)] = validRecord(t, runeName(i))
		}
		if err := ValidateSet(set); err == nil {
			t.Fatal("oversized approval set was accepted")
		}
	})
	t.Run("duplicate canonical path", func(t *testing.T) {
		first := validRecord(t, "tool")
		second := first
		second.Name = "other"
		set := map[string]Record{"tool": first, "other": second}
		if err := ValidateSet(set); err == nil {
			t.Fatal("duplicate canonical path was accepted")
		}
	})
}

func runeName(i int) string {
	// names stay within the descriptor rule: lowercase letter then digits/dashes
	return string(rune('a'+i%26)) + "-" + string(rune('a'+(i/26)%26)) + string(rune('0'+i%10))
}
