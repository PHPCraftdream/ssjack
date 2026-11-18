package tarin_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

func TestExtractWritesFileBytes(t *testing.T) {
	_, dir := testRoot(t)
	big := make([]byte, 150000)
	for i := range big {
		big[i] = byte(i*31 ^ i>>3)
	}
	empty := []byte(nil)
	nested := []byte("nested content")
	entries := []tarEntry{
		{Header: &tar.Header{Name: "big.bin", Mode: 0644, Size: int64(len(big)), Format: tar.FormatPAX}, Body: big},
		{Header: &tar.Header{Name: "empty.bin", Mode: 0644, Format: tar.FormatPAX}},
		{Header: &tar.Header{Name: "d/nested.txt", Mode: 0644, Size: int64(len(nested)), Format: tar.FormatPAX}, Body: nested},
	}
	archive := tarArchive(t, entries)
	staging, err := NewStaging("out", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	computed, err := ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{"big.bin": big, "empty.bin": empty, "d/nested.txt": nested}
	if len(computed.Files) != len(want) {
		t.Fatalf("computed files: %d", len(computed.Files))
	}
	for _, entry := range computed.Files {
		content, ok := want[entry.Path]
		if !ok {
			t.Fatalf("unexpected computed file %q", entry.Path)
		}
		if entry.Size != int64(len(content)) {
			t.Fatalf("entry %q size: %d", entry.Path, entry.Size)
		}
		if entry.SHA256 != sha256.Sum256(content) {
			t.Fatalf("entry %q digest mismatch", entry.Path)
		}
		got, err := os.ReadFile(filepath.Join(staging.Path(), filepath.FromSlash(entry.Path)))
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("on-disk bytes for %q differ: %v", entry.Path, err)
		}
	}
	info, err := os.Stat(filepath.Join(staging.Path(), "empty.bin"))
	if err != nil || info.Size() != 0 {
		t.Fatalf("empty.bin missing or not empty: %v", err)
	}
	if err := staging.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractTarDotLayout(t *testing.T) {
	t.Run("dot-slash root", func(t *testing.T) {
		_, dir := testRoot(t)
		archive := tarArchive(t, []tarEntry{
			{Header: &tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0755, Format: tar.FormatPAX}},
			{Header: &tar.Header{Name: "./a/", Typeflag: tar.TypeDir, Mode: 0755, Format: tar.FormatPAX}},
			{Header: &tar.Header{Name: "./a/b.txt", Mode: 0644, Size: 5, Format: tar.FormatPAX}, Body: []byte("hello")},
			{Header: &tar.Header{Name: "./c.txt", Mode: 0644, Size: 1, Format: tar.FormatPAX}, Body: []byte("x")},
		})
		staging, err := NewStaging("out", dir, false)
		if err != nil {
			t.Fatal(err)
		}
		computed, err := ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if len(computed.Dirs) != 1 || computed.Dirs[0] != "a" {
			t.Fatalf("computed dirs: %v", computed.Dirs)
		}
		if len(computed.Files) != 2 || computed.Files[0].Path != "a/b.txt" || computed.Files[1].Path != "c.txt" {
			t.Fatalf("computed files: %v", computed.Files)
		}
		for _, entry := range computed.Files {
			if containsDotComponent(entry.Path) {
				t.Fatalf("entry %q still contains a dot component", entry.Path)
			}
		}
		got, err := os.ReadFile(filepath.Join(staging.Path(), "a", "b.txt"))
		if err != nil || !bytes.Equal(got, []byte("hello")) {
			t.Fatalf("on-disk bytes differ: %v", err)
		}
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("dot root", func(t *testing.T) {
		_, dir := testRoot(t)
		archive := tarArchive(t, []tarEntry{
			{Header: &tar.Header{Name: ".", Typeflag: tar.TypeDir, Mode: 0755, Format: tar.FormatPAX}},
			{Header: &tar.Header{Name: "a/", Typeflag: tar.TypeDir, Mode: 0755, Format: tar.FormatPAX}},
			{Header: &tar.Header{Name: "a/f.txt", Mode: 0644, Size: 1, Format: tar.FormatPAX}, Body: []byte("x")},
		})
		staging, err := NewStaging("out", dir, false)
		if err != nil {
			t.Fatal(err)
		}
		computed, err := ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if len(computed.Dirs) != 1 || computed.Dirs[0] != "a" {
			t.Fatalf("computed dirs: %v", computed.Dirs)
		}
		if len(computed.Files) != 1 || computed.Files[0].Path != "a/f.txt" {
			t.Fatalf("computed files: %v", computed.Files)
		}
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("traversal after strip", func(t *testing.T) {
		_, dir := testRoot(t)
		archive := tarArchive(t, []tarEntry{
			{Header: &tar.Header{Name: "./../evil.txt", Mode: 0644, Size: 1, Format: tar.FormatPAX}, Body: []byte("x")},
		})
		staging, err := NewStaging("out", dir, false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
		requireClass(t, err, transfercore.ClassRefusedPath, dir)
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("regular dot entry", func(t *testing.T) {
		_, dir := testRoot(t)
		archive := tarArchive(t, []tarEntry{
			{Header: &tar.Header{Name: ".", Mode: 0644, Size: 1, Format: tar.FormatPAX}, Body: []byte("x")},
		})
		staging, err := NewStaging("out", dir, false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
		requireClass(t, err, transfercore.ClassIntegrity, dir)
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("dot component remains", func(t *testing.T) {
		_, dir := testRoot(t)
		archive := tarArchive(t, []tarEntry{
			{Header: &tar.Header{Name: "././nested.txt", Mode: 0644, Size: 1, Format: tar.FormatPAX}, Body: []byte("x")},
		})
		staging, err := NewStaging("out", dir, false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
		requireClass(t, err, transfercore.ClassRefusedPath, dir)
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
}

// containsDotComponent reports whether any slash-separated component is ".".
func containsDotComponent(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if part == "." {
			return true
		}
	}
	return false
}
