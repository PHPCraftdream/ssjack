package chunktest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/chunkfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

func TestChunkedDownloadNonLinkFailureIsNotRetried(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 44)
	rig.Put(content)
	rig.Fake.SetReadFault(func(n int) *testfixture.PartFailure {
		return &testfixture.PartFailure{Cut: chunkfixture.ChunkMiB, Err: testfixture.StageErr(24)}
	})

	res, err, _ := rig.Download(rig.Engine, "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
	enginetest.ExpectNoResult(t, res)
	rig.AssertAbsent("big.bin")
	testfixture.NoStagingLeft(t, rig.Root.Dir())
	if n := rig.Fake.ReadCount(); n != 1 {
		t.Fatalf("ReadFile ran %d times, want 1", n)
	}
	if n := len(rig.Fake.Ranges()); n != 0 {
		t.Fatalf("%d range reads ran after a remote exit status", n)
	}
}

func TestChunkedDownloadRangeReadRemoteStatusEndsTheJobAndRemovesStaging(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 45)
	rig.Put(content)
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
	rig.Fake.SetRangeFault(func(n int, rg transferlink.Range) *testfixture.PartFailure {
		if n == 2 {
			return &testfixture.PartFailure{Cut: 1000, Err: testfixture.StageErr(24)}
		}
		return nil
	})

	_, err, _ := rig.Download(rig.Engine, "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
	if n := len(rig.Fake.Ranges()); n != 2 {
		t.Fatalf("%d range reads ran, want 2 (a remote status is not retried)", n)
	}
	rig.AssertAbsent("big.bin")
	testfixture.NoStagingLeft(t, rig.Root.Dir())
}

func TestChunkedDownloadProfileCarriesOverToTheNextJob(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 46)
	rig.Put(content)
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))

	if _, err, _ := rig.Download(rig.Engine, "one.bin", false); err != nil {
		t.Fatalf("first job: %v", err)
	}
	streams := rig.Fake.ReadCount()
	res, err, _ := rig.Download(rig.Engine, "two.bin", false)
	if err != nil {
		t.Fatalf("second job: %v", err)
	}
	if n := rig.Fake.ReadCount(); n != streams {
		t.Fatalf("the second job streamed (%d streams, was %d): it ignored the profile", n, streams)
	}
	// No stream: one session per part, one assembly.
	if res.Mode != transferengine.ModeChunked || res.Attempts != res.ChunksDone+1 {
		t.Fatalf("second job result = %+v", res)
	}
	rig.AssertDownloaded("two.bin", content)
}

func TestChunkedDownloadPublicationSemanticsMatchTheStream(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("overwrite %v", overwrite), func(t *testing.T) {
			rig := chunkfixture.NewDLRig(t)
			content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 47)
			rig.Put(content)
			testfixture.WriteLocalFile(t, rig.Root, "big.bin", []byte("old content"))
			// Complete parts from an earlier process: no stream is tried, so the
			// existing destination is met by the chunked path itself.
			rig.Seed("big.bin", content,
				transferlink.Range{Off: 0, Len: chunkfixture.ChunkMiB},
				transferlink.Range{Off: chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB},
				transferlink.Range{Off: 2 * chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB})

			_, err, _ := rig.Download(rig.FreshEngine(), "big.bin", overwrite)
			if overwrite {
				if err != nil {
					t.Fatalf("Download: %v", err)
				}
				rig.AssertDownloaded("big.bin", content)
				return
			}
			testfixture.ExpectClass(t, err, transfercore.ClassExists)
			got, readErr := os.ReadFile(rig.LocalPath("big.bin"))
			if readErr != nil || !bytes.Equal(got, []byte("old content")) {
				t.Fatal("the existing destination was modified")
			}
			testfixture.NoStagingLeft(t, rig.Root.Dir())
			if n := len(rig.Fake.Ranges()); n != 0 {
				t.Fatalf("%d range reads ran for an existing destination", n)
			}
		})
	}
}

func TestChunkedDownloadDestinationAppearingBeforePublicationIsExists(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 48)
	rig.Put(content)
	rig.Seed("big.bin", content,
		transferlink.Range{Off: 0, Len: chunkfixture.ChunkMiB},
		transferlink.Range{Off: chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB},
		transferlink.Range{Off: 2 * chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB})
	// Look 1 is the preflight, look 2 the one before the assembly.
	rig.Fake.SetOnStat(func(n int) {
		if n == 2 {
			testfixture.WriteLocalFile(t, rig.Root, "big.bin", []byte("late arrival"))
		}
	})

	_, err, _ := rig.Download(rig.FreshEngine(), "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassExists)
	got, readErr := os.ReadFile(rig.LocalPath("big.bin"))
	if readErr != nil || !bytes.Equal(got, []byte("late arrival")) {
		t.Fatal("the late destination was modified")
	}
	testfixture.NoStagingLeft(t, rig.Root.Dir())
}

func TestChunkedDownloadForbiddenControlDirectoryIsRefused(t *testing.T) {
	for _, size := range []int{4 << 10, 3 * chunkfixture.ChunkMiB} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			rig := chunkfixture.NewDLRig(t)
			content := chunkfixture.ChunkContent(size, 49)
			rig.Put(content)

			res, err, _ := rig.Download(rig.Engine, ".git/big.bin", false)
			testfixture.ExpectClass(t, err, transfercore.ClassRefusedPath)
			enginetest.ExpectNoResult(t, res)
			if n := rig.Fake.CallCount("ReadRange") + rig.Fake.CallCount("ReadFile"); n != 0 {
				t.Fatalf("%d reads ran for a forbidden destination", n)
			}
			entries, readErr := os.ReadDir(rig.Root.Dir())
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("a refused destination left %v behind (%v)", entries, readErr)
			}
		})
	}
}

func TestChunkedDownloadCollectsStaleStagingAtPreflight(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(64<<10, 50) // small: the collection runs anyway
	rig.Put(content)
	stale1 := rig.StaleStage("big.bin", content, 72*time.Hour, 1)
	stale2 := rig.StaleStage("big.bin", content, 25*time.Hour, 2)
	young := rig.StaleStage("big.bin", content, 22*time.Hour, 3)
	foreign := filepath.Join(rig.Root.Dir(), ".ssjack-transfer-"+fmt.Sprintf("%032x", 4))
	chunkfixture.MakeForeignStage(t, foreign)
	oneShot := filepath.Join(rig.Root.Dir(), ".ssjack-transfer-0123456789ab")
	chunkfixture.MakeForeignStage(t, oneShot)
	plain := testfixture.WriteLocalFile(t, rig.Root, "plain.txt", []byte("plain"))
	beforeForeign, beforeOneShot := chunkfixture.DlSnapshot(t, foreign), chunkfixture.DlSnapshot(t, oneShot)

	if _, err, _ := rig.Download(rig.Engine, "big.bin", false); err != nil {
		t.Fatalf("Download: %v", err)
	}
	for _, gone := range []string{stale1, stale2} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Fatalf("idle staging %s survived the later transfer", filepath.Base(gone))
		}
	}
	for _, kept := range []string{young, foreign, oneShot, plain} {
		if _, err := os.Lstat(kept); err != nil {
			t.Fatalf("%s was removed: %v", filepath.Base(kept), err)
		}
	}
	if chunkfixture.DlSnapshot(t, foreign) != beforeForeign || chunkfixture.DlSnapshot(t, oneShot) != beforeOneShot {
		t.Fatal("a foreign object was modified")
	}
}

func TestChunkedDownloadNeverCollectsItsOwnIdleStaging(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 51)
	rig.Put(content)
	rig.Seed("big.bin", content, transferlink.Range{Off: 0, Len: 512 << 10})
	dir := rig.StageDir("big.bin")
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "marker"), old, old); err != nil {
		t.Fatal(err)
	}

	res, err, _ := rig.Download(rig.FreshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	if n := rig.Fake.ReadCount(); n != 0 {
		t.Fatalf("the idle own staging was collected and the file streamed (%d streams)", n)
	}
	if ranges := rig.Fake.Ranges(); len(ranges) == 0 || ranges[0].Off != 512<<10 {
		t.Fatalf("range reads = %v, want a resume after the part found", ranges)
	}
	if res.Mode != transferengine.ModeChunked {
		t.Fatalf("result = %+v", res)
	}
}

func TestChunkedDownloadStagingOfAnotherPreHashIsDiscarded(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 52)
	rig.Put(content)
	// Same key (size and time), but the parts belong to other bytes: the marker
	// records another pre-hash.
	other := chunkfixture.ChunkContent(len(content), 53)
	rig.SeedWith("big.bin", sha256.Sum256(other), chunkfixture.SeedParts(other,
		transferlink.Range{Off: 0, Len: chunkfixture.ChunkMiB},
		transferlink.Range{Off: chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB},
		transferlink.Range{Off: 2 * chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB}))

	res, err, _ := rig.Download(rig.FreshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	want := transferengine.Result{Kind: transferengine.KindFile, Files: 1, Bytes: int64(len(content)), SHA256: chunkfixture.SumHex(content)}
	if res != want {
		t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
	}
	if n := len(rig.Fake.Ranges()); n != 0 {
		t.Fatalf("%d range reads ran: the parts of another version were reused", n)
	}
}

func TestChunkedDownloadAssemblyDropKeepsThePartsAndTriesAgain(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 55)
	rig.Put(content)
	rig.Seed("big.bin", content,
		transferlink.Range{Off: 0, Len: chunkfixture.ChunkMiB},
		transferlink.Range{Off: chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB},
		transferlink.Range{Off: 2 * chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB})
	// Look 1 is the preflight, look 2 the first one before the assembly.
	rig.Fake.SetStatFault(func(n int) error {
		if n == 2 {
			return transferremote.LinkFailure()
		}
		return nil
	})

	res, err, _ := rig.Download(rig.FreshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	if n := rig.Fake.StatCount(); n != 3 {
		t.Fatalf("StatSource ran %d times, want the preflight, the dropped look and its retry", n)
	}
	if n := len(rig.Fake.Ranges()); n != 0 {
		t.Fatalf("%d parts were read again after the assembly drop", n)
	}
	if res.Mode != transferengine.ModeChunked || res.Attempts != 2 {
		t.Fatalf("result = %+v, want two assembly attempts", res)
	}
}

func TestChunkedDownloadAssemblyKeepsDroppingThenAnotherEnginePublishes(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 56)
	rig.Put(content)
	rig.Seed("big.bin", content,
		transferlink.Range{Off: 0, Len: chunkfixture.ChunkMiB},
		transferlink.Range{Off: chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB},
		transferlink.Range{Off: 2 * chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB})
	rig.Fake.SetStatFault(func(n int) error {
		if n >= 2 {
			return transferremote.LinkFailure()
		}
		return nil
	})

	res, err, _ := rig.Download(rig.FreshEngine(), "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassLinkUnstable)
	if n := rig.Fake.StatCount(); n != 1+transferlink.MaxNoProgress {
		t.Fatalf("StatSource ran %d times, want the preflight and %d dropped looks", n, transferlink.MaxNoProgress)
	}
	if res.Mode != transferengine.ModeChunked || res.Bytes != int64(len(content)) || res.Attempts != transferlink.MaxNoProgress {
		t.Fatalf("stranded result = %+v, want every byte verified in parts", res)
	}
	rig.AssertAbsent("big.bin")
	if kept := rig.Kept("big.bin", content); chunkfixture.SumLens(kept) != int64(len(content)) || len(kept) != 3 {
		t.Fatalf("the parts did not stay intact: %v", kept)
	}

	rig.Fake.SetStatFault(nil)
	res2, err2, _ := rig.Download(rig.FreshEngine(), "big.bin", false)
	if err2 != nil {
		t.Fatalf("second call after the assembly drops: %v", err2)
	}
	rig.AssertDownloaded("big.bin", content)
	if n := len(rig.Fake.Ranges()); n != 0 || rig.Fake.ReadCount() != 0 {
		t.Fatalf("second call read %d ranges and %d streams; want only the assembly", n, rig.Fake.ReadCount())
	}
	if res2.Bytes != int64(len(content)) || res2.Mode != transferengine.ModeChunked {
		t.Fatalf("second result = %+v", res2)
	}
}

func TestChunkedDownloadVanishedStagingRestartsFromZeroWithMonotoneBytes(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 57)
	rig.Put(content)
	dir := rig.StageDir("big.bin")
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
	// Look 1 is the preflight, looks 2 and 3 precede parts 1 and 2, look 4
	// precedes part 3: someone removes the staging just before it.
	rig.Fake.SetOnStat(func(n int) {
		if n == 4 {
			if err := os.RemoveAll(dir); err != nil {
				t.Errorf("remove staging: %v", err)
			}
		}
	})

	res, err, log := rig.Download(rig.Engine, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	chunkfixture.AssertMonotone(t, log.Items)
	if res.Bytes != int64(len(content)) || res.Mode != transferengine.ModeChunked {
		t.Fatalf("result = %+v", res)
	}
	if n := len(rig.Fake.Ranges()); n < 4 {
		t.Fatalf("%d range reads ran, want the lost parts to be read again", n)
	}
}

func TestChunkedDownloadRemovesIgnoredEntriesFoundOnResume(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 58)
	rig.Put(content)
	rig.Seed("big.bin", content, transferlink.Range{Off: 0, Len: 512 << 10})
	dir := rig.StageDir("big.bin")
	// A lying part, a stale temporary file and a left-over assembly.
	junk := map[string]string{
		"part-524288-524288":          "a lying size",
		"part-0-4.abc123.tmp":         "stale",
		"assembled.abc123.tmp":        "stale assembly",
		"part-1048576-524288.xyz.tmp": "stale",
	}
	for name, data := range junk {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if _, err, _ := rig.Download(rig.FreshEngine(), "big.bin", false); err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	if first := rig.Fake.Ranges()[0]; first.Off != 512<<10 {
		t.Fatalf("first range = %v, want the lying entry's range to be read again", first)
	}
}

func TestChunkedDownloadPreflightRetriesADroppedLook(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 60)
	rig.Put(content)
	rig.Fake.SetStatFault(func(n int) error {
		if n == 1 {
			return transferremote.LinkFailure()
		}
		return nil
	})
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))

	res, err, _ := rig.Download(rig.Engine, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	if res.Mode != transferengine.ModeChunked {
		t.Fatalf("result = %+v: the retried look did not enable chunking", res)
	}
}

func TestChunkedDownloadDirectoriesAreNeverChunked(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	rig.Fake.Mkdir("/data/tree")
	rig.Fake.Put("/data/tree/big.bin", chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 61))
	rig.Fake.FailTarOut = transferremote.LinkFailure()

	res, err := chunkfixture.ExpectFinish(t, 30*time.Second, func() (transferengine.Result, error) {
		return rig.Engine.Download(context.Background(), rig.Root, "/data/tree", "out", false, nil)
	})
	if err == nil {
		t.Fatal("a dropped directory transfer succeeded")
	}
	enginetest.ExpectNoResult(t, res)
	rig.AssertAbsent("out")
	testfixture.NoStagingLeft(t, rig.Root.Dir())
	for _, call := range []string{"StatSource", "ReadRange", "ReadFile"} {
		if n := rig.Fake.CallCount(call); n != 0 {
			t.Fatalf("%s ran %d times for a directory", call, n)
		}
	}
	if n := rig.Fake.CallCount("TarOut"); n != 1 {
		t.Fatalf("TarOut ran %d times, want 1 (a dropped directory transfer has no second attempt)", n)
	}
}
