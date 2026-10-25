package ssjack

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLicenseTextIncludesProjectAndPinnedDependencyNotices(t *testing.T) {
	text := LicenseText()
	for _, required := range []string{
		"MIT OR Apache-2.0", "Copyright (c) 2026 ssjack contributors",
		"Apache License", "Version 2.0, January 2004", "MIT License",
		"The Ktav contributors", "Go MCP SDK Authors", "JSON Schema Go Project Authors",
		"Kohei YOSHIDA", "The Go Authors", "v0.8.1", "v1.0.0", "v0.3.0", "v3.0.2",
		"v0.53.0", "v0.46.0", "v0.44.0", "go1.26.0", "Additional IP Rights Grant (Patents)",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing distribution notice %q", required)
		}
	}
	if strings.Count(text, "Copyright (c) 2009 The Go Authors.") != 1 {
		t.Fatal("identical Go Authors license must be retained once")
	}
}

func normalizeLicense(data []byte) string {
	return strings.TrimSpace(string(bytes.ReplaceAll(data, []byte{13, 10}, []byte{10})))
}

func TestNoticesMatchLinkedModuleLicenses(t *testing.T) {
	output, err := exec.Command("go", "list", "-mod=readonly", "-deps", "-json", "./cmd/ssjack").Output()
	if err != nil {
		t.Fatalf("inspect linked module inventory: %v", err)
	}
	type module struct {
		Path, Version, Dir string
		Main               bool
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	seen := make(map[string]bool)
	for {
		var item struct{ Module *module }
		err := decoder.Decode(&item)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		m := item.Module
		if m == nil || m.Main || seen[m.Path] {
			continue
		}
		seen[m.Path] = true
		if !strings.Contains(thirdPartyNotices, m.Path+" "+m.Version) {
			t.Fatalf("unlisted linked module: %s %s", m.Path, m.Version)
		}
		content, err := os.ReadFile(filepath.Join(m.Dir, "LICENSE"))
		if err != nil {
			t.Fatalf("read pinned module license %s: %v", m.Path, err)
		}
		if !strings.Contains(thirdPartyNotices, normalizeLicense(content)) {
			t.Fatalf("license text differs from linked module: %s", m.Path)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no runtime dependency licenses were inspected")
	}
	content, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(thirdPartyNotices, normalizeLicense(content)) {
		t.Fatal("Go runtime license is missing")
	}
}
