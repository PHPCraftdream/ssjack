//go:build !windows

package transferlocal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Regression for the live transfer acceptance: the published directory kept
// the owner-only mode of its staging root.
func TestPublishedDirectoryRootIsNotPrivate(t *testing.T) {
	root, _ := testRoot(t)
	staging, err := NewStaging("dest", root.Dir(), false)
	if err != nil {
		t.Fatal(err)
	}
	archive := tarArchive(t, []tarEntry{dirEntry("sub"), regEntry("sub/f.txt", 3)})
	if _, err := ExtractTar(bytes.NewReader(archive), staging, nil, transfercore.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(staging.Path())
	if err != nil || before.Mode().Perm() != 0700 {
		t.Fatalf("staging root is not private before publication: %v %v", before, err)
	}
	if err := staging.Publish(KindDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root.Dir(), "dest"))
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("published directory mode = %v, want 0755 (%v)", info.Mode().Perm(), err)
	}
}
