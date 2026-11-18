package chunk_test

import (
	"testing"

	. "github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/localtest"
)

var (
	writeFile            = localtest.WriteFile
	requireClass         = localtest.RequireClass
	requireNoPath        = localtest.RequireNoPath
	tarArchive           = localtest.TarArchive
	patchFirstHeaderSize = localtest.PatchFirstHeaderSize
	regEntry             = localtest.RegEntry
	dirEntry             = localtest.DirEntry
)

type tarEntry = localtest.TarEntry

// testRoot returns a Root registered on a symlink-free temp directory.
func testRoot(t *testing.T) (*Root, string) {
	t.Helper()
	dir := localtest.TempDir(t)
	root, err := ParseRoot(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	return root, dir
}
