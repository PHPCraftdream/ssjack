package transferlocal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestBuildTarNestedRelRoundTrip(t *testing.T) {
	root, dir := testRoot(t)
	deep := make([]byte, 600)
	for i := range deep {
		deep[i] = byte(i * 11)
	}
	writeFile(t, filepath.Join(dir, "a", "b", "deep.bin"), deep)
	writeFile(t, filepath.Join(dir, "a", "b", "sub", "x.txt"), []byte("x"))
	walked, err := root.WalkSource("a/b", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(walked.Dirs) != 1 || walked.Dirs[0] != "sub" {
		t.Fatalf("walked dirs: %v", walked.Dirs)
	}
	if len(walked.Files) != 2 || walked.Files[0].Path != "deep.bin" || walked.Files[1].Path != "sub/x.txt" {
		t.Fatalf("walked files: %v", walked.Files)
	}
	var tarBytes bytes.Buffer
	if err := root.BuildTar(&tarBytes, "a/b", walked); err != nil {
		t.Fatal(err)
	}
	staging, err := NewStaging("rt", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	computed, err := ExtractTar(bytes.NewReader(tarBytes.Bytes()), staging, &walked, transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !sameManifest(computed, walked) {
		t.Fatal("computed manifest differs from walked manifest")
	}
	if err := staging.Publish(KindDir); err != nil {
		t.Fatal(err)
	}
	requireNoPath(t, staging.Path())
	got, err := os.ReadFile(filepath.Join(dir, "rt", "deep.bin"))
	if err != nil || !bytes.Equal(got, deep) {
		t.Fatalf("published deep.bin differs: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(dir, "rt", "sub", "x.txt"))
	if err != nil || !bytes.Equal(got, []byte("x")) {
		t.Fatalf("published x.txt differs: %v", err)
	}
}

func TestBuildTarSingleFileRoundTrip(t *testing.T) {
	root, dir := testRoot(t)
	content := []byte("single file bytes")
	writeFile(t, filepath.Join(dir, "top.bin"), content)
	walked, err := root.WalkSource("top.bin", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(walked.Files) != 1 || walked.Files[0].Path != "top.bin" {
		t.Fatalf("walked files: %v", walked.Files)
	}
	var tarBytes bytes.Buffer
	if err := root.BuildTar(&tarBytes, "top.bin", walked); err != nil {
		t.Fatal(err)
	}
	staging, err := NewStaging("copy.bin", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	computed, err := ExtractTar(bytes.NewReader(tarBytes.Bytes()), staging, &walked, transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(computed.Files) != 1 || computed.Files[0].Path != "top.bin" {
		t.Fatalf("computed files: %v", computed.Files)
	}
	if computed.Files[0].Size != int64(len(content)) {
		t.Fatalf("computed size: %d", computed.Files[0].Size)
	}
	got, err := os.ReadFile(filepath.Join(staging.Path(), "top.bin"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("on-disk bytes differ: %v", err)
	}
	if err := staging.Abort(); err != nil {
		t.Fatal(err)
	}
}
