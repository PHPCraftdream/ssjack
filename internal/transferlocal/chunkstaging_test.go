package transferlocal

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
)

func chunkSum(b byte) [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = b
	}
	return s
}

func chunkKey(n int) string { return fmt.Sprintf("%032x", n) }

func openChunk(t *testing.T, root *Root, rel, key string, sum [32]byte, overwrite, create bool) (*ChunkStaging, ChunkState) {
	t.Helper()
	s, state, err := root.OpenChunkStaging(rel, key, sum, overwrite, create)
	if err != nil {
		t.Fatalf("OpenChunkStaging: %v", err)
	}
	return s, state
}

func commitPart(t *testing.T, s *ChunkStaging, off int64, data []byte) {
	t.Helper()
	w, err := s.CreatePart(transferlink.Range{Off: off, Len: int64(len(data))})
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if n, err := w.Write(data); err != nil || n != len(data) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// dirState renders the entries of one directory (names and file contents).
func dirState(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, entry := range entries {
		b.WriteString(entry.Name())
		if entry.Type().IsRegular() {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			b.WriteString(" " + string(data))
		} else if entry.IsDir() {
			b.WriteString(" [" + dirState(t, filepath.Join(dir, entry.Name())) + "]")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func entryList(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestChunkStagingCreateReuseAndRemove(t *testing.T) {
	root, dir := testRoot(t)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := chunkKey(1)
	sum := chunkSum(7)

	if s, state := openChunk(t, root, "sub/out.bin", key, sum, false, false); s != nil || state != ChunkAbsent {
		t.Fatalf("lookup of a missing staging = %v, %v", s, state)
	}
	s, state := openChunk(t, root, "sub/out.bin", key, sum, false, true)
	if s == nil || state != ChunkCreated {
		t.Fatalf("create = %v, %v", s, state)
	}
	stageDir := filepath.Join(dir, "sub", ".ssjack-transfer-"+key)
	if s.path != stageDir {
		t.Fatalf("staging path = %q, want %q", s.path, stageDir)
	}
	marker, err := os.ReadFile(filepath.Join(stageDir, "marker"))
	if err != nil || string(marker) != formatChunkMarker(key, sum) {
		t.Fatalf("marker = %q, %v", marker, err)
	}
	if !strings.HasPrefix(string(marker), "SSJACK-STAGING 1 "+key+"\n") {
		t.Fatalf("marker does not start with the shared magic and key: %q", marker)
	}

	again, state := openChunk(t, root, "sub/out.bin", key, sum, false, false)
	if again == nil || state != ChunkReused {
		t.Fatalf("lookup of an own staging = %v, %v", again, state)
	}
	if err := again.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	requireNoPath(t, stageDir)
	if err := again.Remove(); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
	if err := s.Remove(); err != nil {
		t.Fatalf("Remove of an already removed staging: %v", err)
	}
}

func TestChunkStagingRefusesBadDestinations(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(2)
	for _, rel := range []string{".git/out.bin", "a/.ssh/out.bin", "nul.bin", "bad:name", "../out.bin", "/abs.bin", "missing-parent/out.bin"} {
		s, _, err := root.OpenChunkStaging(rel, key, chunkSum(1), false, true)
		if s != nil {
			t.Fatalf("%q: a staging was opened", rel)
		}
		requireClass(t, err, transfercore.ClassRefusedPath, dir)
	}
	if got := entryList(t, dir); len(got) != 0 {
		t.Fatalf("a refused destination left %v behind", got)
	}
	if _, _, err := root.OpenChunkStaging("out.bin", "not-a-key", chunkSum(1), false, true); err == nil {
		t.Fatal("an invalid key was accepted")
	}
	if _, _, err := root.OpenChunkStaging("out.bin", strings.ToUpper(chunkKey(255)), chunkSum(1), false, true); err == nil {
		t.Fatal("an upper-case key was accepted")
	}
}

func TestChunkStagingForeignObjectsAreNeverUsedOrRemoved(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, path, key string)
	}{
		{"no-marker", func(t *testing.T, path, key string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(path, "keep"), []byte("keep"))
		}},
		{"marker-of-another-key", func(t *testing.T, path, key string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(path, "marker"), []byte(formatChunkMarker(chunkKey(999), chunkSum(1))))
			writeFile(t, filepath.Join(path, "part-0-1"), []byte("x"))
		}},
		{"marker-without-source-line", func(t *testing.T, path, key string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(path, "marker"), []byte("SSJACK-STAGING 1 "+key+"\n"))
		}},
		{"marker-is-a-directory", func(t *testing.T, path, key string) {
			if err := os.MkdirAll(filepath.Join(path, "marker"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"regular-file", func(t *testing.T, path, key string) {
			writeFile(t, path, []byte("not a directory"))
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, dir := testRoot(t)
			key := chunkKey(100 + i)
			tc.build(t, filepath.Join(dir, ".ssjack-transfer-"+key), key)
			before := dirState(t, dir)

			for _, create := range []bool{false, true} {
				s, state := openChunk(t, root, "out.bin", key, chunkSum(1), false, create)
				if s != nil || state != ChunkForeign {
					t.Fatalf("create=%v: open = %v, %v; want foreign", create, s, state)
				}
			}
			old := time.Now().Add(-100 * time.Hour)
			_ = os.Chtimes(filepath.Join(dir, ".ssjack-transfer-"+key, "marker"), old, old)
			if n := root.CollectStaleChunkStaging("out.bin", ""); n != 0 {
				t.Fatalf("garbage collection removed %d foreign objects", n)
			}
			if after := dirState(t, dir); after != before {
				t.Fatalf("a foreign object was modified:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

func TestChunkStagingOfAnotherSourceVersionIsDiscarded(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(3)
	s, _ := openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	commitPart(t, s, 0, []byte("old bytes"))

	if got, state := openChunk(t, root, "out.bin", key, chunkSum(2), false, false); got != nil || state != ChunkAbsent {
		t.Fatalf("lookup with another pre-hash = %v, %v; want the staging discarded", got, state)
	}
	requireNoPath(t, filepath.Join(dir, ".ssjack-transfer-"+key))

	s, _ = openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	commitPart(t, s, 0, []byte("old bytes"))
	fresh, state := openChunk(t, root, "out.bin", key, chunkSum(2), false, true)
	if fresh == nil || state != ChunkCreated {
		t.Fatalf("create with another pre-hash = %v, %v; want a fresh staging", fresh, state)
	}
	parts, overflow, err := fresh.ListParts(100, 10)
	if err != nil || overflow || len(parts) != 0 {
		t.Fatalf("the discarded staging leaked parts: %v %v %v", parts, overflow, err)
	}
}

func TestChunkStagingPartLifecycle(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(4)
	s, _ := openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	stageDir := filepath.Join(dir, ".ssjack-transfer-"+key)
	marker := filepath.Join(stageDir, "marker")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(marker, old, old); err != nil {
		t.Fatal(err)
	}

	// A part commits only with exactly its length.
	w, err := s.CreatePart(transferlink.Range{Off: 0, Len: 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	requireClass(t, w.Commit(), transfercore.ClassIntegrity)
	if got := entryList(t, stageDir); !reflect.DeepEqual(got, []string{"marker"}) {
		t.Fatalf("a short part left %v", got)
	}

	// Abort removes the temporary file and is idempotent.
	w, err = s.CreatePart(transferlink.Range{Off: 0, Len: 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("ab")); err != nil || w.Written() != 2 {
		t.Fatalf("Written = %d, %v", w.Written(), err)
	}
	w.Abort()
	w.Abort()
	if _, err := w.Write([]byte("c")); err == nil {
		t.Fatal("a write after Abort succeeded")
	}
	if got := entryList(t, stageDir); !reflect.DeepEqual(got, []string{"marker"}) {
		t.Fatalf("an aborted part left %v", got)
	}

	// More bytes than the part length are refused, and nothing is written.
	w, err = s.CreatePart(transferlink.Range{Off: 0, Len: 4})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.Write([]byte("abcde")); err == nil || n != 0 {
		t.Fatalf("overrun write = %d, %v", n, err)
	}
	w.Abort()

	commitPart(t, s, 0, []byte("abcd"))
	if got := entryList(t, stageDir); !reflect.DeepEqual(got, []string{"marker", "part-0-4"}) {
		t.Fatalf("entries after a part = %v", got)
	}
	info, err := os.Stat(marker)
	if err != nil || time.Since(info.ModTime()) > time.Hour {
		t.Fatalf("a completed part did not refresh the marker time: %v %v", info, err)
	}
	// The same range again replaces the part.
	commitPart(t, s, 0, []byte("abcd"))

	parts, overflow, err := s.ListParts(12, 10)
	if err != nil || overflow || !reflect.DeepEqual(parts, []transferlink.Range{{Off: 0, Len: 4}}) {
		t.Fatalf("ListParts = %v %v %v", parts, overflow, err)
	}
}

func TestChunkStagingListPartsBuildsCoverageAndRemovesJunk(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(5)
	s, _ := openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	stageDir := filepath.Join(dir, ".ssjack-transfer-"+key)
	files := map[string]string{
		"part-0-4":         "abcd",
		"part-4-4":         "efg",  // shorter than its name says
		"part-0-2":         "ab",   // overlaps an accepted part
		"part-8-4":         "ijkl", // ends exactly at the file
		"part-10-4":        "mnop", // ends past the file
		"part-007-5":       "12345",
		"part-9-1.abc.tmp": "x",
		"assembled.x.tmp":  "stale assembly",
		"payload":          "stale payload",
		"unknown.txt":      "not ours",
	}
	for name, data := range files {
		writeFile(t, filepath.Join(stageDir, name), []byte(data))
	}

	parts, overflow, err := s.ListParts(12, 20)
	if err != nil || overflow {
		t.Fatalf("ListParts = %v %v %v", parts, overflow, err)
	}
	want := []transferlink.Range{{Off: 0, Len: 4}, {Off: 8, Len: 4}}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("parts = %v, want %v", parts, want)
	}
	left := entryList(t, stageDir)
	wantLeft := []string{"marker", "part-0-4", "part-8-4", "unknown.txt"}
	if !reflect.DeepEqual(left, wantLeft) {
		t.Fatalf("entries left = %v, want %v", left, wantLeft)
	}
}

func TestChunkStagingListPartsOverflowTouchesNothing(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(6)
	s, _ := openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	stageDir := filepath.Join(dir, ".ssjack-transfer-"+key)
	for _, name := range []string{"part-0-1", "part-1-1", "part-2-1", "part-9-1.tmp"} {
		writeFile(t, filepath.Join(stageDir, name), []byte("x"))
	}
	before := dirState(t, stageDir)
	parts, overflow, err := s.ListParts(100, 2)
	if err != nil || !overflow || parts != nil {
		t.Fatalf("ListParts = %v %v %v, want overflow", parts, overflow, err)
	}
	if after := dirState(t, stageDir); after != before {
		t.Fatal("an overflowing listing modified the staging")
	}
}

func TestChunkStagingListPartsOfAVanishedStaging(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(7)
	s, _ := openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	if err := os.RemoveAll(filepath.Join(dir, ".ssjack-transfer-"+key)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ListParts(10, 10); !errors.Is(err, ErrChunkStagingGone) {
		t.Fatalf("ListParts = %v, want ErrChunkStagingGone", err)
	}
	if _, err := s.CreatePart(transferlink.Range{Off: 0, Len: 1}); !errors.Is(err, ErrChunkStagingGone) {
		t.Fatalf("CreatePart = %v, want ErrChunkStagingGone", err)
	}
}

func stagedAbcdefghij(t *testing.T, root *Root, overwrite bool) (*ChunkStaging, []transferlink.Range) {
	t.Helper()
	s, _ := openChunk(t, root, "out.bin", chunkKey(8), chunkSum(1), overwrite, true)
	commitPart(t, s, 4, []byte("efgh"))
	commitPart(t, s, 0, []byte("abcd"))
	commitPart(t, s, 8, []byte("ij"))
	return s, []transferlink.Range{{Off: 0, Len: 4}, {Off: 4, Len: 4}, {Off: 8, Len: 2}}
}

func TestChunkStagingAssembleAndPublish(t *testing.T) {
	root, dir := testRoot(t)
	s, parts := stagedAbcdefghij(t, root, false)
	if err := s.CheckDestination(); err != nil {
		t.Fatalf("CheckDestination: %v", err)
	}
	sum, err := s.Assemble(context.Background(), parts, 10)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if want := sha256.Sum256([]byte("abcdefghij")); sum != want {
		t.Fatalf("digest = %x, want %x", sum, want)
	}
	stageDir := filepath.Join(dir, ".ssjack-transfer-"+chunkKey(8))
	var assembled int
	for _, name := range entryList(t, stageDir) {
		if strings.HasPrefix(name, "assembled.") && strings.HasSuffix(name, ".tmp") {
			assembled++
		}
	}
	if assembled != 1 {
		t.Fatalf("%d assembled files, want 1: %v", assembled, entryList(t, stageDir))
	}
	// A second assembly replaces the first one.
	if _, err := s.Assemble(context.Background(), parts, 10); err != nil {
		t.Fatalf("second Assemble: %v", err)
	}
	if err := s.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "out.bin"))
	if err != nil || string(got) != "abcdefghij" {
		t.Fatalf("published file = %q, %v", got, err)
	}
	if names := entryList(t, dir); !reflect.DeepEqual(names, []string{"out.bin"}) {
		t.Fatalf("directory holds %v, want only the published file", names)
	}
	if err := s.Remove(); err != nil {
		t.Fatalf("Remove after Publish: %v", err)
	}
	if err := s.Publish(); err == nil {
		t.Fatal("a second Publish succeeded")
	}
}

func TestChunkStagingPublishSemantics(t *testing.T) {
	t.Run("exists without overwrite", func(t *testing.T) {
		root, dir := testRoot(t)
		writeFile(t, filepath.Join(dir, "out.bin"), []byte("old"))
		s, parts := stagedAbcdefghij(t, root, false)
		requireClass(t, s.CheckDestination(), transfercore.ClassExists)
		if _, err := s.Assemble(context.Background(), parts, 10); err != nil {
			t.Fatal(err)
		}
		requireClass(t, s.Publish(), transfercore.ClassExists)
		if got, _ := os.ReadFile(filepath.Join(dir, "out.bin")); string(got) != "old" {
			t.Fatalf("the existing destination became %q", got)
		}
		if err := s.Remove(); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if names := entryList(t, dir); !reflect.DeepEqual(names, []string{"out.bin"}) {
			t.Fatalf("directory holds %v", names)
		}
	})
	t.Run("overwrite", func(t *testing.T) {
		root, dir := testRoot(t)
		writeFile(t, filepath.Join(dir, "out.bin"), []byte("old"))
		s, parts := stagedAbcdefghij(t, root, true)
		if err := s.CheckDestination(); err != nil {
			t.Fatalf("CheckDestination with overwrite: %v", err)
		}
		if _, err := s.Assemble(context.Background(), parts, 10); err != nil {
			t.Fatal(err)
		}
		if err := s.Publish(); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "out.bin")); string(got) != "abcdefghij" {
			t.Fatalf("the destination is %q", got)
		}
		if names := entryList(t, dir); !reflect.DeepEqual(names, []string{"out.bin"}) {
			t.Fatalf("directory holds %v", names)
		}
	})
	t.Run("overwrite onto a directory", func(t *testing.T) {
		root, dir := testRoot(t)
		if err := os.Mkdir(filepath.Join(dir, "out.bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		s, parts := stagedAbcdefghij(t, root, true)
		if _, err := s.Assemble(context.Background(), parts, 10); err != nil {
			t.Fatal(err)
		}
		requireClass(t, s.Publish(), transfercore.ClassRefusedPath)
		if info, err := os.Stat(filepath.Join(dir, "out.bin")); err != nil || !info.IsDir() {
			t.Fatal("the destination directory was replaced")
		}
	})
}

func TestChunkStagingAssembleRejectsBadParts(t *testing.T) {
	cases := map[string]func(t *testing.T, stageDir string){
		"missing part": func(t *testing.T, stageDir string) {
			if err := os.Remove(filepath.Join(stageDir, "part-4-4")); err != nil {
				t.Fatal(err)
			}
		},
		"truncated part": func(t *testing.T, stageDir string) {
			writeFile(t, filepath.Join(stageDir, "part-4-4"), []byte("ef"))
		},
		"part replaced by a directory": func(t *testing.T, stageDir string) {
			p := filepath.Join(stageDir, "part-4-4")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, damage := range cases {
		t.Run(strings.ReplaceAll(name, " ", "-"), func(t *testing.T) {
			root, dir := testRoot(t)
			s, parts := stagedAbcdefghij(t, root, false)
			stageDir := filepath.Join(dir, ".ssjack-transfer-"+chunkKey(8))
			damage(t, stageDir)
			if _, err := s.Assemble(context.Background(), parts, 10); !errors.Is(err, ErrChunkPartInvalid) {
				t.Fatalf("Assemble = %v, want ErrChunkPartInvalid", err)
			}
			for _, entry := range entryList(t, stageDir) {
				if strings.HasPrefix(entry, "assembled.") {
					t.Fatalf("a failed assembly left %q", entry)
				}
			}
			if err := s.Publish(); err == nil {
				t.Fatal("Publish succeeded without an assembled file")
			}
		})
	}
}

func TestChunkStagingAssembleRefusesWrongTilingAndHonoursCancel(t *testing.T) {
	root, dir := testRoot(t)
	s, parts := stagedAbcdefghij(t, root, false)
	stageDir := filepath.Join(dir, ".ssjack-transfer-"+chunkKey(8))
	if _, err := s.Assemble(context.Background(), parts[:2], 10); err == nil {
		t.Fatal("Assemble accepted parts that leave a gap")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Assemble(ctx, parts, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("Assemble under a cancelled context = %v", err)
	}
	for _, entry := range entryList(t, stageDir) {
		if strings.HasPrefix(entry, "assembled.") {
			t.Fatalf("a cancelled assembly left %q", entry)
		}
	}
}

func makeStaged(t *testing.T, root *Root, key string, age time.Duration) string {
	t.Helper()
	s, state, err := root.OpenChunkStaging("out.bin", key, chunkSum(1), false, true)
	if err != nil || state != ChunkCreated {
		t.Fatalf("OpenChunkStaging(%s) = %v, %v", key, state, err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(filepath.Join(s.path, "marker"), old, old); err != nil {
		t.Fatal(err)
	}
	return s.path
}

func TestCollectStaleChunkStaging(t *testing.T) {
	root, dir := testRoot(t)
	stale1 := makeStaged(t, root, chunkKey(10), 72*time.Hour)
	stale2 := makeStaged(t, root, chunkKey(11), 25*time.Hour)
	young := makeStaged(t, root, chunkKey(12), 20*time.Hour)
	excluded := makeStaged(t, root, chunkKey(13), 72*time.Hour)
	foreign := filepath.Join(dir, ".ssjack-transfer-"+chunkKey(14))
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	oneShot := filepath.Join(dir, ".ssjack-transfer-0123456789ab")
	if err := os.Mkdir(oneShot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(oneShot, "marker"), []byte(formatChunkMarker(chunkKey(15), chunkSum(1))))
	old := time.Now().Add(-100 * time.Hour)
	_ = os.Chtimes(filepath.Join(oneShot, "marker"), old, old)
	plain := filepath.Join(dir, "plain.txt")
	writeFile(t, plain, []byte("plain"))

	if n := root.CollectStaleChunkStaging("out.bin", chunkKey(13)); n != 2 {
		t.Fatalf("collected %d, want the 2 idle ones", n)
	}
	requireNoPath(t, stale1)
	requireNoPath(t, stale2)
	for _, kept := range []string{young, excluded, foreign, oneShot, plain} {
		if _, err := os.Lstat(kept); err != nil {
			t.Fatalf("%s was removed: %v", filepath.Base(kept), err)
		}
	}
	// The current job's own staging is not collected even when it is idle.
	if n := root.CollectStaleChunkStaging("out.bin", ""); n != 1 {
		t.Fatalf("collected %d without an exclusion, want the formerly excluded one", n)
	}
}

func TestCollectStaleChunkStagingIsBounded(t *testing.T) {
	root, dir := testRoot(t)
	for i := 0; i < ChunkGCLimit+4; i++ {
		makeStaged(t, root, chunkKey(100+i), 72*time.Hour)
	}
	if n := root.CollectStaleChunkStaging("out.bin", ""); n != ChunkGCLimit {
		t.Fatalf("first collection removed %d, want %d", n, ChunkGCLimit)
	}
	if left := len(entryList(t, dir)); left != 4 {
		t.Fatalf("%d staging directories left, want 4", left)
	}
	if n := root.CollectStaleChunkStaging("out.bin", ""); n != 4 {
		t.Fatalf("second collection removed %d, want 4", n)
	}
}

func TestCollectStaleChunkStagingRefusedDestinationsCollectNothing(t *testing.T) {
	root, dir := testRoot(t)
	makeStaged(t, root, chunkKey(20), 72*time.Hour)
	for _, rel := range []string{".git/out.bin", "missing/out.bin", "nul.bin"} {
		if n := root.CollectStaleChunkStaging(rel, ""); n != 0 {
			t.Fatalf("%s: collected %d", rel, n)
		}
	}
	if len(entryList(t, dir)) != 1 {
		t.Fatal("the staging was removed through a refused destination")
	}
}

func TestChunkStagingFreeBytes(t *testing.T) {
	root, _ := testRoot(t)
	s, _ := openChunk(t, root, "out.bin", chunkKey(30), chunkSum(1), false, true)
	free, ok := s.FreeBytes()
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		if !ok || free <= 0 {
			t.Fatalf("FreeBytes = %d, %v; want a positive size on %s", free, ok, runtime.GOOS)
		}
	default:
		if ok {
			t.Fatal("FreeBytes claims support on an unsupported platform")
		}
	}
}

func TestChunkMarkerFormat(t *testing.T) {
	key := chunkKey(40)
	text := formatChunkMarker(key, chunkSum(0xab))
	m, ok := parseChunkMarker(text)
	if !ok || m.key != key || m.sum != chunkSum(0xab) {
		t.Fatalf("round trip = %+v, %v", m, ok)
	}
	for _, bad := range []string{
		"", "SSJACK-STAGING 1 " + key + "\n",
		strings.TrimSuffix(text, "\n"),
		text + "extra\n",
		strings.Replace(text, "SSJACK-STAGING 1", "SSJACK-STAGING 2", 1),
		strings.Replace(text, "SSJACK-SOURCE-SHA256 ", "SSJACK-SOURCE-SHA256 zz", 1),
		strings.Replace(text, key, strings.ToUpper(chunkKey(255)), 1),
	} {
		if _, ok := parseChunkMarker(bad); ok {
			t.Fatalf("marker %q was accepted", bad)
		}
	}
}
