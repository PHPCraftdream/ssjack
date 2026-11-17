//go:build !windows

package transferlocal

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transferlink"
)

func TestChunkStagingIsPrivate(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(50)
	s, _ := openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	stageDir := filepath.Join(dir, ".ssjack-transfer-"+key)
	info, err := os.Stat(stageDir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("staging directory = %v, %v; want mode 0700", info, err)
	}
	commitPart(t, s, 0, []byte("abcd"))
	for _, name := range []string{"marker", "part-0-4"} {
		info, err := os.Stat(filepath.Join(stageDir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s = %v, %v; want mode 0600", name, info, err)
		}
	}
}

func TestChunkStagingUnixForeignObjects(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, dir, path, key string)
	}{
		{"mode-0755", func(t *testing.T, dir, path, key string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(path, "marker"), []byte(formatChunkMarker(key, chunkSum(1))))
			writeFile(t, filepath.Join(path, "part-0-1"), []byte("x"))
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory-symlink", func(t *testing.T, dir, path, key string) {
			real := filepath.Join(dir, "real-staging")
			if err := os.Mkdir(real, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(real, "marker"), []byte(formatChunkMarker(key, chunkSum(1))))
			writeFile(t, filepath.Join(real, "part-0-1"), []byte("x"))
			if err := os.Symlink(real, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"marker-is-a-symlink", func(t *testing.T, dir, path, key string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			real := filepath.Join(dir, "real-marker")
			writeFile(t, real, []byte(formatChunkMarker(key, chunkSum(1))))
			if err := os.Symlink(real, filepath.Join(path, "marker")); err != nil {
				t.Fatal(err)
			}
		}},
		{"marker-is-hard-linked", func(t *testing.T, dir, path, key string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			other := filepath.Join(dir, "other-name")
			writeFile(t, other, []byte(formatChunkMarker(key, chunkSum(1))))
			if err := os.Link(other, filepath.Join(path, "marker")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, dir := testRoot(t)
			key := chunkKey(200 + i)
			path := filepath.Join(dir, ".ssjack-transfer-"+key)
			tc.build(t, dir, path, key)
			old := time.Now().Add(-100 * time.Hour)
			_ = os.Chtimes(filepath.Join(path, "marker"), old, old)
			before := dirState(t, dir)

			for _, create := range []bool{false, true} {
				s, state := openChunk(t, root, "out.bin", key, chunkSum(1), false, create)
				if s != nil || state != ChunkForeign {
					t.Fatalf("create=%v: open = %v, %v; want foreign", create, s, state)
				}
			}
			if n := root.CollectStaleChunkStaging("out.bin", ""); n != 0 {
				t.Fatalf("garbage collection removed %d foreign objects", n)
			}
			if after := dirState(t, dir); after != before {
				t.Fatalf("a foreign object was modified:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

func TestChunkStagingRemoveRefusesAStagingReplacedByALink(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(60)
	s, _ := openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	stageDir := filepath.Join(dir, ".ssjack-transfer-"+key)
	if err := os.RemoveAll(stageDir); err != nil {
		t.Fatal(err)
	}
	// Someone puts a link to a directory with the same marker at the name.
	real := filepath.Join(dir, "real-staging")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(real, "marker"), []byte(formatChunkMarker(key, chunkSum(1))))
	writeFile(t, filepath.Join(real, "keep"), []byte("keep"))
	if err := os.Symlink(real, stageDir); err != nil {
		t.Fatal(err)
	}
	before := dirState(t, real)
	if err := s.Remove(); err == nil {
		t.Fatal("Remove deleted a link it did not create")
	}
	if info, err := os.Lstat(stageDir); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was removed: %v, %v", info, err)
	}
	if after := dirState(t, real); after != before {
		t.Fatal("the link target was modified")
	}
}

func TestChunkStagingListPartsRemovesLinksWithoutFollowingThem(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(61)
	s, _ := openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	stageDir := filepath.Join(dir, ".ssjack-transfer-"+key)
	outside := filepath.Join(dir, "outside.txt")
	writeFile(t, outside, []byte("abcd"))
	if err := os.Symlink(outside, filepath.Join(stageDir, "part-0-4")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(stageDir, "part-4-4")); err != nil {
		t.Fatal(err)
	}
	commitPart(t, s, 8, []byte("ijkl"))

	parts, overflow, err := s.ListParts(12, 10)
	if err != nil || overflow || !reflect.DeepEqual(parts, []transferlink.Range{{Off: 8, Len: 4}}) {
		t.Fatalf("ListParts = %v %v %v", parts, overflow, err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "abcd" {
		t.Fatalf("the link target changed: %q, %v", got, err)
	}
	if got := entryList(t, stageDir); !reflect.DeepEqual(got, []string{"marker", "part-8-4"}) {
		t.Fatalf("entries left = %v", got)
	}
}

func TestChunkStagingAssembleRefusesASymlinkedPart(t *testing.T) {
	root, dir := testRoot(t)
	key := chunkKey(62)
	s, _ := openChunk(t, root, "out.bin", key, chunkSum(1), false, true)
	stageDir := filepath.Join(dir, ".ssjack-transfer-"+key)
	outside := filepath.Join(dir, "outside.txt")
	writeFile(t, outside, []byte("abcd"))
	if err := os.Symlink(outside, filepath.Join(stageDir, "part-0-4")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Assemble(context.Background(), []transferlink.Range{{Off: 0, Len: 4}}, 4); err == nil {
		t.Fatal("a symlinked part was assembled")
	}
}
