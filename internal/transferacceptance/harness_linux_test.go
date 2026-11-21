//go:build linux

package transferacceptance

import (
	"path/filepath"
	"testing"

	chunks "github.com/PHPCraftdream/ssjack/internal/transferacceptance/internal/chunks"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// TestTransferBusyboxAcceptance covers a deliberate subset on a real BusyBox
// shell and applet PATH. Directory content/count/manifest equality is checked
// in both directions; the separate full GNU acceptance retains its timestamp
// assertions, which this subset does not establish for BusyBox tar.
func TestTransferBusyboxAcceptance(t *testing.T) {
	t.Run("roundtrip-file-both-directions", transferScenario(scenarioRoundTripFile))
	t.Run("roundtrip-directory-basic-both-directions", transferScenario(scenarioRoundTripDirectoryBasic))
	t.Run("roundtrip-zero-byte-and-empty-directory", transferScenario(scenarioRoundTripEmpty))
	t.Run("roundtrip-names-with-spaces-and-non-ascii", transferScenario(scenarioRoundTripNames))
	t.Run("overwrite-replaces-file-and-directory", transferScenario(scenarioOverwrite))
	t.Run("refuse-symlink-destination", transferScenario(scenarioRefuseSymlinkDestination))
	t.Run("overwrite-failure-leaves-old-destination", transferScenario(scenarioOverwriteFailure))
	t.Run("refuse-destination-exists", transferScenario(scenarioRefuseDestinationExists))
	t.Run("failure-hash-mismatch-corruption", transferScenario(scenarioFailureCorruption))
	t.Run("chunk-remote-probe-capabilities", transferScenario(chunks.ScenarioChunkProbe))
	t.Run("chunk-remote-staging-lifecycle-and-foreign-objects", transferScenario(chunks.ScenarioChunkStagingLifecycle))
	t.Run("chunk-remote-part-upload-and-listing", transferScenario(chunks.ScenarioChunkPartsAndListing))
	t.Run("chunk-remote-assembly-and-publication", transferScenario(chunks.ScenarioChunkAssemblyAndPublication))
	t.Run("chunk-remote-garbage-collection", transferScenario(chunks.ScenarioChunkGarbageCollection))
	t.Run("chunk-remote-read-stat-and-disk", transferScenario(chunks.ScenarioChunkReadStatAndDisk))
	t.Run("chunk-upload-stream-drop-continues-chunked", transferScenario(chunks.ScenarioChunkUploadStreamDrop))
	t.Run("chunk-upload-drop-mid-chunk", transferScenario(chunks.ScenarioChunkUploadDropMidChunk))
	t.Run("chunk-upload-drop-during-assembly", transferScenario(chunks.ScenarioChunkUploadDropDuringAssembly))
	t.Run("chunk-upload-resume-by-new-engine", transferScenario(chunks.ScenarioChunkUploadResumeByNewEngine))
	t.Run("chunk-upload-source-changed", transferScenario(chunks.ScenarioChunkUploadSourceChanged))
	t.Run("chunk-upload-stale-staging-collected", transferScenario(chunks.ScenarioChunkUploadStaleStagingCollected))
	t.Run("chunk-upload-stall-detected-and-resumed", transferScenario(chunks.ScenarioChunkUploadStallDetectedAndResumed))
	t.Run("chunk-upload-leftover-assembly-cleaned", transferScenario(chunks.ScenarioChunkUploadLeftoverAssemblyCleaned))
	t.Run("chunk-download-stream-drop-continues-chunked", transferScenario(chunks.ScenarioChunkDownloadStreamDrop))
	t.Run("chunk-download-drop-mid-chunk", transferScenario(chunks.ScenarioChunkDownloadDropMidChunk))
	t.Run("chunk-download-drop-during-assembly", transferScenario(chunks.ScenarioChunkDownloadDropDuringAssembly))
	t.Run("chunk-download-resume-by-new-engine", transferScenario(chunks.ScenarioChunkDownloadResumeByNewEngine))
	t.Run("chunk-download-source-changed", transferScenario(chunks.ScenarioChunkDownloadSourceChanged))
	t.Run("chunk-download-stale-staging-collected", transferScenario(chunks.ScenarioChunkDownloadStaleStagingCollected))
	t.Run("chunk-download-stall-detected-and-resumed", transferScenario(chunks.ScenarioChunkDownloadStallDetectedAndResumed))
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
	checkStatusState(t, "directory upload", up, "done")
	checkStatusKind(t, "directory upload", up, "directory")
	checkStatusCount(t, "directory upload", "files", up.Files, 2)
	checkStatusCount(t, "directory upload", "dirs", up.Dirs, 2)
	if up.ManifestSHA256 == "" {
		t.Fatal("directory upload status manifest_sha256: got absent, want present")
	}
	CompareTrees(t, filepath.Join(s.rootDir, "tree"), remote)
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": remote, "local": "returned",
	}))
	checkStatusState(t, "directory download", down, "done")
	checkStatusKind(t, "directory download", down, "directory")
	checkStatusCount(t, "directory download", "files", down.Files, up.Files)
	checkStatusCount(t, "directory download", "dirs", down.Dirs, up.Dirs)
	checkStatusDigest(t, "directory download", "manifest_sha256", down.ManifestSHA256, up.ManifestSHA256)
	CompareTrees(t, filepath.Join(s.rootDir, "tree"), filepath.Join(s.rootDir, "returned"))
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
	assertNoLeaks(t, c, payload)
}
