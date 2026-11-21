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
	runTransferScenario(t, "roundtrip-file-both-directions", scenarioRoundTripFile)
	runTransferScenario(t, "roundtrip-directory-basic-both-directions", scenarioRoundTripDirectoryBasic)
	runTransferScenario(t, "roundtrip-zero-byte-and-empty-directory", scenarioRoundTripEmpty)
	runTransferScenario(t, "roundtrip-names-with-spaces-and-non-ascii", scenarioRoundTripNames)
	runTransferScenario(t, "overwrite-replaces-file-and-directory", scenarioOverwrite)
	runTransferScenario(t, "refuse-symlink-destination", scenarioRefuseSymlinkDestination)
	runTransferScenario(t, "overwrite-failure-leaves-old-destination", scenarioOverwriteFailure)
	runTransferScenario(t, "refuse-destination-exists", scenarioRefuseDestinationExists)
	runTransferScenario(t, "failure-hash-mismatch-corruption", scenarioFailureCorruption)
	runTransferScenario(t, "chunk-remote-probe-capabilities", chunks.ScenarioChunkProbe)
	runTransferScenario(t, "chunk-remote-staging-lifecycle-and-foreign-objects", chunks.ScenarioChunkStagingLifecycle)
	runTransferScenario(t, "chunk-remote-part-upload-and-listing", chunks.ScenarioChunkPartsAndListing)
	runTransferScenario(t, "chunk-remote-assembly-and-publication", chunks.ScenarioChunkAssemblyAndPublication)
	runTransferScenario(t, "chunk-remote-garbage-collection", chunks.ScenarioChunkGarbageCollection)
	runTransferScenario(t, "chunk-remote-read-stat-and-disk", chunks.ScenarioChunkReadStatAndDisk)
	runTransferScenario(t, "chunk-upload-stream-drop-continues-chunked", chunks.ScenarioChunkUploadStreamDrop)
	runTransferScenario(t, "chunk-upload-drop-mid-chunk", chunks.ScenarioChunkUploadDropMidChunk)
	runTransferScenario(t, "chunk-upload-drop-during-assembly", chunks.ScenarioChunkUploadDropDuringAssembly)
	runTransferScenario(t, "chunk-upload-resume-by-new-engine", chunks.ScenarioChunkUploadResumeByNewEngine)
	runTransferScenario(t, "chunk-upload-source-changed", chunks.ScenarioChunkUploadSourceChanged)
	runTransferScenario(t, "chunk-upload-stale-staging-collected", chunks.ScenarioChunkUploadStaleStagingCollected)
	runTransferScenario(t, "chunk-upload-stall-detected-and-resumed", chunks.ScenarioChunkUploadStallDetectedAndResumed)
	runTransferScenario(t, "chunk-upload-leftover-assembly-cleaned", chunks.ScenarioChunkUploadLeftoverAssemblyCleaned)
	runTransferScenario(t, "chunk-download-stream-drop-continues-chunked", chunks.ScenarioChunkDownloadStreamDrop)
	runTransferScenario(t, "chunk-download-drop-mid-chunk", chunks.ScenarioChunkDownloadDropMidChunk)
	runTransferScenario(t, "chunk-download-drop-during-assembly", chunks.ScenarioChunkDownloadDropDuringAssembly)
	runTransferScenario(t, "chunk-download-resume-by-new-engine", chunks.ScenarioChunkDownloadResumeByNewEngine)
	runTransferScenario(t, "chunk-download-source-changed", chunks.ScenarioChunkDownloadSourceChanged)
	runTransferScenario(t, "chunk-download-stale-staging-collected", chunks.ScenarioChunkDownloadStaleStagingCollected)
	runTransferScenario(t, "chunk-download-stall-detected-and-resumed", chunks.ScenarioChunkDownloadStallDetectedAndResumed)
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
