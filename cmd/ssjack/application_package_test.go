package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validClawwrightMetadata = `{"name":"@phpcraftdream/clawwright","version":"0.1.2","ssjackRuntime":{"requirements":{"optional":true,"protocol":1,"chunkSize":16384,"capabilities":["exec","stdin","binary","backpressure","cancel"],"cancellation":"connection-only"}}}`

func fixtureClawwrightPackage(t *testing.T, root string) string {
	t.Helper()
	entry := filepath.Join(root, "dist", "entry", "bin.js")
	if err := os.MkdirAll(filepath.Dir(entry), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte("// fixture, never executed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(validClawwrightMetadata), 0600); err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestClawwrightDeclaredCompatibility(t *testing.T) {
	root := t.TempDir()
	entry := fixtureClawwrightPackage(t, root)
	if err := validateClawwrightPackage(entry); err != nil {
		t.Fatal(err)
	}
	for _, metadata := range []string{
		"",
		`{"name":"@phpcraftdream/clawwright","version":"0.1.2"}`,
		strings.Replace(validClawwrightMetadata, "@phpcraftdream/clawwright", "other/package", 1),
		strings.Replace(validClawwrightMetadata, `"optional":true`, `"optional":false`, 1),
		strings.Replace(validClawwrightMetadata, `"protocol":1`, `"protocol":2`, 1),
		strings.Replace(validClawwrightMetadata, `"chunkSize":16384`, `"chunkSize":8192`, 1),
		strings.Replace(validClawwrightMetadata, "connection-only", "unsupported", 1),
		strings.Replace(validClawwrightMetadata, `,"cancel"`, "", 1),
		validClawwrightMetadata + "\xff",
		strings.Repeat(" ", 64*1024+1),
	} {
		if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(metadata), 0600); err != nil {
			t.Fatal(err)
		}
		if err := validateClawwrightPackage(entry); err == nil {
			t.Fatal("incompatible, malformed or oversized metadata was accepted")
		}
	}
	if err := validateClawwrightPackage(filepath.Join(root, "custom.js")); err == nil {
		t.Fatal("unassociated entry layout was accepted")
	}
	if err := os.Remove(filepath.Join(root, "package.json")); err != nil {
		t.Fatal(err)
	}
	if err := validateClawwrightPackage(entry); err == nil {
		t.Fatal("missing metadata was accepted")
	}
	if err := os.Mkdir(filepath.Join(root, "package.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateClawwrightPackage(entry); err == nil {
		t.Fatal("metadata directory was accepted")
	}
}
