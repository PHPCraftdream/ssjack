package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestClawwrightRegistrationWithoutUnlock(t *testing.T) {
	if options, err := registeredClawwright("", "", "", "", "main", nil); err != nil || options != nil {
		t.Fatal("standalone keeper unexpectedly registered Clawwright")
	}
	for _, args := range [][4]string{{"", "entry.js", "", ""}, {"", "", "guest", "user"}, {t.TempDir(), "entry.js", "guest", ""}} {
		if _, err := registeredClawwright(args[0], args[1], args[2], args[3], "main", nil); err == nil {
			t.Fatal("incomplete registration accepted")
		}
	}
	bin := t.TempDir()
	node := "node"
	if runtime.GOOS == "windows" {
		node = "node.exe"
	}
	if err := os.WriteFile(filepath.Join(bin, node), []byte("fixture, never executed"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	root := t.TempDir()
	entry := filepath.Join(root, "checked entry.js")
	if err := os.WriteFile(entry, []byte("// fixture, never executed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	options, err := registeredClawwright(root, "checked entry.js", "guest", "operator", "fixed", nil)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	canonicalEntry, err := filepath.EvalSymlinks(entry)
	if err != nil {
		t.Fatal(err)
	}
	if options.Directory != canonicalRoot || len(options.Command) != 2 || options.Command[1] != canonicalEntry || !filepath.IsAbs(options.Command[0]) || options.Profile != "fixed" {
		t.Fatalf("registration changed fixed inputs: %+v", options)
	}
	if _, err := registeredClawwright(root, root, "", "", "main", nil); err == nil {
		t.Fatal("entry directory accepted")
	}
	if _, err := registeredClawwright(root, "missing.js", "", "", "main", nil); err == nil {
		t.Fatal("missing entry accepted")
	}
	if code, err := run(context.Background(), []string{"--clawwright-entry", entry, "run", "harness"}); code == 0 || err == nil {
		t.Fatal("orphan entry reached vault unlock")
	}
}

func TestInstalledClawwrightEntryDoesNotExecuteShim(t *testing.T) {
	root := t.TempDir()
	if runtime.GOOS == "windows" {
		entry, err := installedClawwrightEntry(filepath.Join(root, "clawwright.cmd"))
		if err != nil || entry != filepath.Join(root, "node_modules", "@phpcraftdream", "clawwright", "dist", "entry", "bin.js") {
			t.Fatal("npm shim was not resolved to its Node entry")
		}
		return
	}
	entry := filepath.Join(root, "bin.js")
	if err := os.WriteFile(entry, []byte("// fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(root, "clawwright")
	if err := os.Symlink(entry, shim); err != nil {
		t.Fatal(err)
	}
	got, err := installedClawwrightEntry(shim)
	want, canonicalErr := filepath.EvalSymlinks(entry)
	if err != nil || canonicalErr != nil || got != want {
		t.Fatal("npm executable symlink was not resolved")
	}
	if _, err := installedClawwrightEntry(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing installed entry accepted")
	}
}
