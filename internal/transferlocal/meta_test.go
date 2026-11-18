package transferlocal

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

var (
	metaFileTime = time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	metaDirTime  = time.Date(2019, 8, 9, 10, 11, 12, 0, time.UTC)
)

// Regression for the live transfer acceptance: a directory upload published
// every file with the 1970 epoch because the tar headers carried no time.
func TestBuildTarCarriesModTimes(t *testing.T) {
	root, dir := testRoot(t)
	writeFile(t, filepath.Join(dir, "tree", "sub", "x.txt"), []byte("x"))
	if err := os.Chtimes(filepath.Join(dir, "tree", "sub", "x.txt"), metaFileTime, metaFileTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(dir, "tree", "sub"), metaDirTime, metaDirTime); err != nil {
		t.Fatal(err)
	}
	walked, err := root.WalkSource("tree", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	if err := root.BuildTar(&stream, "tree", walked); err != nil {
		t.Fatal(err)
	}
	got := map[string]time.Time{}
	reader := tar.NewReader(&stream)
	for {
		hdr, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[hdr.Name] = hdr.ModTime
	}
	if len(got) != 2 || !got["sub/"].Equal(metaDirTime) || !got["sub/x.txt"].Equal(metaFileTime) {
		t.Fatalf("tar headers lost the modification times: %v", got)
	}
}

// Regression for the live acceptance: GNU tar sets a directory time once the
// stream leaves the directory, so "directories first, files after" left every
// directory with the time of the last child written into it.
func TestBuildTarKeepsEachSubtreeTogether(t *testing.T) {
	root, dir := testRoot(t)
	writeFile(t, filepath.Join(dir, "tree", "a", "b", "x.txt"), []byte("x"))
	writeFile(t, filepath.Join(dir, "tree", "a", "y.txt"), []byte("y"))
	writeFile(t, filepath.Join(dir, "tree", "a-b.txt"), []byte("z"))
	walked, err := root.WalkSource("tree", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	if err := root.BuildTar(&stream, "tree", walked); err != nil {
		t.Fatal(err)
	}
	var names []string
	reader := tar.NewReader(&stream)
	for {
		hdr, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}
	want := []string{"a/", "a/b/", "a/b/x.txt", "a/y.txt", "a-b.txt"}
	if len(names) != len(want) {
		t.Fatalf("archive order = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("archive order = %v, want %v", names, want)
		}
	}
}

func TestExtractRestoresModTimesAndSkipsAbsurdOnes(t *testing.T) {
	root, _ := testRoot(t)
	staging, err := NewStaging("dest", root.Dir(), false)
	if err != nil {
		t.Fatal(err)
	}
	withTime := func(entry tarEntry, modTime time.Time) tarEntry {
		entry.Header.ModTime = modTime
		entry.Header.Format = tar.FormatPAX // USTAR cannot hold the year 2400
		return entry
	}
	archive := tarArchive(t, []tarEntry{
		withTime(dirEntry("a"), metaDirTime),
		withTime(dirEntry("a/b"), metaDirTime.Add(time.Hour)),
		withTime(regEntry("a/b/f.txt", 3), metaFileTime),
		withTime(regEntry("epoch.txt", 3), time.Unix(0, 0)),
		withTime(regEntry("future.txt", 3), time.Date(2400, 1, 1, 0, 0, 0, 0, time.UTC)),
	})
	if _, err := ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := staging.Publish(KindDir); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root.Dir(), "dest")
	for path, want := range map[string]time.Time{
		"a/b/f.txt": metaFileTime,
		"a/b":       metaDirTime.Add(time.Hour),
		"a":         metaDirTime,
	} {
		info, err := os.Stat(filepath.Join(dest, filepath.FromSlash(path)))
		if err != nil || !info.ModTime().Equal(want) {
			t.Fatalf("%s: modification time %v, want %v (%v)", path, info.ModTime(), want, err)
		}
	}
	// An unset or absurd header time leaves the time of the write.
	for _, name := range []string{"epoch.txt", "future.txt"} {
		info, err := os.Stat(filepath.Join(dest, name))
		if err != nil || info.ModTime().Before(time.Now().Add(-time.Hour)) || info.ModTime().After(time.Now().Add(time.Hour)) {
			t.Fatalf("%s: absurd header time was restored: %v (%v)", name, info.ModTime(), err)
		}
	}
}
