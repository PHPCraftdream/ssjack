//go:build linux

package transferacceptance

import (
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// TestTransferBusyboxAcceptance covers a deliberate subset on a real BusyBox
// shell and applet PATH. Directory content/count/manifest equality is checked
// in both directions; the separate full GNU acceptance retains its timestamp
// assertions, which this subset does not establish for BusyBox tar.
func TestTransferBusyboxAcceptance(t *testing.T) {
	t.Run("roundtrip-file-both-directions", scenarioRoundTripFile)
	t.Run("roundtrip-directory-basic-both-directions", scenarioRoundTripDirectoryBasic)
	t.Run("roundtrip-zero-byte-and-empty-directory", scenarioRoundTripEmpty)
	t.Run("roundtrip-names-with-spaces-and-non-ascii", scenarioRoundTripNames)
	t.Run("overwrite-replaces-file-and-directory", scenarioOverwrite)
	t.Run("refuse-symlink-destination", scenarioRefuseSymlinkDestination)
	t.Run("overwrite-failure-leaves-old-destination", scenarioOverwriteFailure)
	t.Run("refuse-destination-exists", scenarioRefuseDestinationExists)
	t.Run("failure-hash-mismatch-corruption", scenarioFailureCorruption)
	// Standalone BusyBox ash can resolve SHA applets independently of restricted PATH,
	// so that fixture cannot establish that hash utilities are absent.
}

// scenarioRoundTripDirectoryBasic compares a simple nested tree in each
// direction, including exact contents, counts and manifest, without asserting
// directory modification-time restoration.
func scenarioRoundTripDirectoryBasic(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	payload := SeedPayload(32*1024, 23)
	WriteTree(t, s.rootDir, map[string][]byte{
		"tree/top.txt":            []byte("top-level"),
		"tree/nested/deeper/blob": payload,
	}, []string{"tree/nested", "tree/nested/deeper"})
	mkdirAll(t, filepath.Join(s.sandbox, "out"))
	remote := s.sandbox + "/out/tree"
	up := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "tree", "remote": remote,
	}))
	if up.State != "done" || up.Kind != "directory" || up.Files != 2 || up.Dirs != 2 || up.ManifestSHA256 == "" {
		t.Fatalf("directory upload status = %+v", up)
	}
	CompareTrees(t, filepath.Join(s.rootDir, "tree"), remote)
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": remote, "local": "returned",
	}))
	if down.State != "done" || down.Kind != "directory" || down.Files != up.Files || down.Dirs != up.Dirs || down.ManifestSHA256 != up.ManifestSHA256 {
		t.Fatalf("directory download status = %+v", down)
	}
	CompareTrees(t, filepath.Join(s.rootDir, "tree"), filepath.Join(s.rootDir, "returned"))
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
	assertNoLeaks(t, c, payload)
}
