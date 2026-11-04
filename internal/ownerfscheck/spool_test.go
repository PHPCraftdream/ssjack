package ownerfscheck

import (
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func TestNativeSpoolCannotBeOpenedByAmbientFilesystemPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store")
	root, err := ownerfs.MakeRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	spool, err := root.Temporary()
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	name := filepath.Join(path, filepath.Base(spool.Name()))
	for _, write := range []bool{false, true} {
		if write {
			if _, err := spool.Write([]byte("synthetic anonymous ciphertext")); err != nil {
				t.Fatal(err)
			}
			if err := spool.Sync(); err != nil {
				t.Fatal(err)
			}
		}
		metadata, err := ownerfs.Stat(spool, true)
		if err != nil || metadata.Links != 0 {
			t.Fatal("native spool lost its anonymous identity")
		}
		if err := inaccessible(name); err != nil {
			t.Fatal(err)
		}
	}
}
