package tarin_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

func TestExtractionRefusals(t *testing.T) {
	defaults := transfercore.DefaultLimits()
	cases := []struct {
		name    string
		entries []tarEntry
		class   transfercore.Class
		limits  transfercore.Limits
		blocked string
	}{
		{"absolute name", []tarEntry{regEntry("/abs/evil.txt", 5)}, transfercore.ClassRefusedPath, defaults, "abs"},
		{"parent traversal", []tarEntry{regEntry("../evil.txt", 5)}, transfercore.ClassRefusedPath, defaults, "../evil.txt"},
		{"backslash name", []tarEntry{regEntry("a\\b.txt", 5)}, transfercore.ClassRefusedPath, defaults, "a\\b.txt"},
		{"colon name", []tarEntry{regEntry("a:b.txt", 5)}, transfercore.ClassRefusedPath, defaults, "a:b.txt"},
		{"reserved CON", []tarEntry{regEntry("CON", 5)}, transfercore.ClassRefusedPath, defaults, "CON"},
		{"reserved con.txt", []tarEntry{regEntry("con.txt", 5)}, transfercore.ClassRefusedPath, defaults, "con.txt"},
		{"reserved NUL.tar.gz", []tarEntry{regEntry("NUL.tar.gz", 5)}, transfercore.ClassRefusedPath, defaults, "NUL.tar.gz"},
		{"reserved COM1", []tarEntry{regEntry("COM1", 5)}, transfercore.ClassRefusedPath, defaults, "COM1"},
		{"reserved LPT9", []tarEntry{regEntry("LPT9", 5)}, transfercore.ClassRefusedPath, defaults, "LPT9"},
		{"trailing dot", []tarEntry{regEntry("x.", 5)}, transfercore.ClassRefusedPath, defaults, "x."},
		{"trailing space", []tarEntry{regEntry("x ", 5)}, transfercore.ClassRefusedPath, defaults, "x "},
		{"control character", []tarEntry{regEntry("a\x01b", 5)}, transfercore.ClassRefusedPath, defaults, ""},
		{"forbidden control directory", []tarEntry{regEntry(".git/config", 5)}, transfercore.ClassRefusedPath, defaults, ".git"},
		{"symlink entry", []tarEntry{{Header: &tar.Header{Name: "lnk", Typeflag: tar.TypeSymlink, Linkname: "elsewhere", Format: tar.FormatUSTAR}}}, transfercore.ClassRefusedPath, defaults, "lnk"},
		{"hard link entry", []tarEntry{{Header: &tar.Header{Name: "lnk", Typeflag: tar.TypeLink, Linkname: "elsewhere", Format: tar.FormatUSTAR}}}, transfercore.ClassRefusedPath, defaults, "lnk"},
		{"char device", []tarEntry{{Header: &tar.Header{Name: "dev", Typeflag: tar.TypeChar, Format: tar.FormatUSTAR}}}, transfercore.ClassRefusedPath, defaults, "dev"},
		{"block device", []tarEntry{{Header: &tar.Header{Name: "dev", Typeflag: tar.TypeBlock, Format: tar.FormatUSTAR}}}, transfercore.ClassRefusedPath, defaults, "dev"},
		{"fifo", []tarEntry{{Header: &tar.Header{Name: "pipe", Typeflag: tar.TypeFifo, Format: tar.FormatUSTAR}}}, transfercore.ClassRefusedPath, defaults, "pipe"},
		{"duplicate name", []tarEntry{regEntry("dup.txt", 5), regEntry("dup.txt", 5)}, transfercore.ClassRefusedPath, defaults, ""},
		{"case-insensitive collision", []tarEntry{regEntry("A.txt", 5), regEntry("a.txt", 5)}, transfercore.ClassRefusedPath, defaults, ""},
		{"pax global header", []tarEntry{
			{Header: &tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, Format: tar.FormatPAX}},
			regEntry("after.txt", 5),
		}, transfercore.ClassRefusedPath, defaults, ""},
		{"entry count", []tarEntry{regEntry("one.txt", 1), regEntry("two.txt", 1), regEntry("three.txt", 1)}, transfercore.ClassLimit,
			transfercore.Limits{MaxBytes: 1 << 20, MaxEntries: 2, MaxPathBytes: 1024, MaxDepth: 64}, ""},
		{"byte limit", []tarEntry{regEntry("one.txt", 10), regEntry("two.txt", 10)}, transfercore.ClassLimit,
			transfercore.Limits{MaxBytes: 15, MaxEntries: 100, MaxPathBytes: 1024, MaxDepth: 64}, ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			root, dir := testRoot(t)
			staging, err := NewStaging("dest", root.Dir(), false)
			if err != nil {
				t.Fatal(err)
			}
			archive := tarArchive(t, c.entries)
			_, err = ExtractTar(bytes.NewReader(archive), staging, nil, c.limits)
			requireClass(t, err, c.class, dir, "evil", "payload")
			if c.blocked != "" {
				requireNoPath(t, filepath.Join(staging.Path(), filepath.FromSlash(c.blocked)))
			}
			if err := staging.Abort(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExtractionSizeLies(t *testing.T) {
	t.Run("size larger than data", func(t *testing.T) {
		root, dir := testRoot(t)
		staging, err := NewStaging("dest", root.Dir(), false)
		if err != nil {
			t.Fatal(err)
		}
		archive := tarArchive(t, []tarEntry{regEntry("five.txt", 5)})
		archive = patchFirstHeaderSize(t, archive, 100000)
		_, err = ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
		requireClass(t, err, transfercore.ClassIntegrity, dir)
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("size smaller than data", func(t *testing.T) {
		root, dir := testRoot(t)
		staging, err := NewStaging("dest", root.Dir(), false)
		if err != nil {
			t.Fatal(err)
		}
		archive := tarArchive(t, []tarEntry{regEntry("ten.txt", 10)})
		archive = patchFirstHeaderSize(t, archive, 5)
		// The header is authoritative: a shorter size extracts a prefix, so the
		// expected manifest is what catches the lie.
		want := transfercore.Manifest{Files: []transfercore.Entry{{Path: "ten.txt", Size: 10, SHA256: sha256.Sum256(bytes.Repeat([]byte("x"), 10))}}}
		_, err = ExtractTar(bytes.NewReader(archive), staging, &want, transfercore.DefaultLimits())
		requireClass(t, err, transfercore.ClassIntegrity, dir)
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("negative size", func(t *testing.T) {
		root, dir := testRoot(t)
		staging, err := NewStaging("dest", root.Dir(), false)
		if err != nil {
			t.Fatal(err)
		}
		archive := tarArchive(t, []tarEntry{regEntry("one.txt", 5)})
		archive = patchFirstHeaderSize(t, archive, 1)
		archive[124] = '-'
		_, err = ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
		requireClass(t, err, transfercore.ClassIntegrity, dir)
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestExtractionWantMismatch(t *testing.T) {
	body := bytes.Repeat([]byte("y"), 7)
	build := func(t *testing.T) (*Staging, []byte) {
		root, _ := testRoot(t)
		staging, err := NewStaging("dest", root.Dir(), false)
		if err != nil {
			t.Fatal(err)
		}
		entry := regEntry("want.txt", 7)
		entry.Body = append([]byte(nil), body...)
		return staging, tarArchive(t, []tarEntry{entry})
	}
	t.Run("wrong hash", func(t *testing.T) {
		staging, archive := build(t)
		want := &transfercore.Manifest{Files: []transfercore.Entry{
			{Path: "want.txt", Size: 7, SHA256: [32]byte{1}},
		}}
		_, err := ExtractTar(bytes.NewReader(archive), staging, want, transfercore.DefaultLimits())
		requireClass(t, err, transfercore.ClassIntegrity, string(body))
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("extra dir", func(t *testing.T) {
		staging, archive := build(t)
		want := &transfercore.Manifest{
			Dirs:  []string{"ghost"},
			Files: []transfercore.Entry{{Path: "want.txt", Size: 7, SHA256: sha256.Sum256(body)}},
		}
		_, err := ExtractTar(bytes.NewReader(archive), staging, want, transfercore.DefaultLimits())
		requireClass(t, err, transfercore.ClassIntegrity, string(body))
		if err := staging.Abort(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestExtractionImplicitDirectories(t *testing.T) {
	root, _ := testRoot(t)
	staging, err := NewStaging("dest", root.Dir(), false)
	if err != nil {
		t.Fatal(err)
	}
	archive := tarArchive(t, []tarEntry{regEntry("implicit/deep/file.txt", 6)})
	computed, err := ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	hasDir := func(name string) bool {
		for _, d := range computed.Dirs {
			if d == name {
				return true
			}
		}
		return false
	}
	if !hasDir("implicit") || !hasDir("implicit/deep") {
		t.Fatalf("implicit dirs missing: %v", computed.Dirs)
	}
	if len(computed.Files) != 1 || computed.Files[0].Path != "implicit/deep/file.txt" {
		t.Fatalf("computed files: %v", computed.Files)
	}
	if err := staging.Publish(KindDir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root.Dir(), "dest", "implicit", "deep", "file.txt"))
	if err != nil || !bytes.Equal(got, []byte("xxxxxx")) {
		t.Fatalf("published implicit file: %v", err)
	}
}

func TestExtractionPayloadCollision(t *testing.T) {
	root, dir := testRoot(t)
	staging, err := NewStaging("dest", root.Dir(), false)
	if err != nil {
		t.Fatal(err)
	}
	file, err := staging.CreatePayload()
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	archive := tarArchive(t, []tarEntry{regEntry("payload", 3)})
	_, err = ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	if err := staging.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractionAfterAbort(t *testing.T) {
	root, _ := testRoot(t)
	staging, err := NewStaging("dest", root.Dir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := staging.Abort(); err != nil {
		t.Fatal(err)
	}
	archive := tarArchive(t, []tarEntry{regEntry("payload", 3)})
	_, err = ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassInternal)
}

func TestExtractionAfterPublish(t *testing.T) {
	root, _ := testRoot(t)
	staging, err := NewStaging("dest", root.Dir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := staging.Publish(KindDir); err != nil {
		t.Fatal(err)
	}
	archive := tarArchive(t, []tarEntry{regEntry("payload", 3)})
	_, err = ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassInternal)
}
