package chunktest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
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

func TestChunkedDownloadStreamDropThenChunkedCompletion(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 31)
	rig.Put(content)
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))

	res, err, log := rig.Download(rig.Engine, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	ranges := rig.Fake.Ranges()
	chunkfixture.AssertTiles(t, int64(len(content)), ranges)
	if res.Kind != transferengine.KindFile || res.Files != 1 || res.Bytes != int64(len(content)) || res.SHA256 != chunkfixture.SumHex(content) {
		t.Fatalf("result = %+v", res)
	}
	if res.Mode != transferengine.ModeChunked || res.ChunksDone != len(ranges) || res.ChunksTotal != len(ranges) {
		t.Fatalf("chunk telemetry = %+v, want chunked with %d parts", res, len(ranges))
	}
	// One stream, one session per part, one assembly.
	if res.Attempts != 1+len(ranges)+1 {
		t.Fatalf("attempts = %d, want %d", res.Attempts, 1+len(ranges)+1)
	}
	if res.BytesPerSecond <= 0 || res.ChunkBytes <= 0 {
		t.Fatalf("telemetry has no speed or chunk size: %+v", res)
	}
	if n := rig.Fake.ReadCount(); n != 1 {
		t.Fatalf("ReadFile ran %d times, want the one dropped stream", n)
	}
	// One look at the source before the key, one before each part, one after
	// the last part.
	if n := rig.Fake.StatCount(); n != len(ranges)+2 {
		t.Fatalf("StatSource ran %d times, want %d", n, len(ranges)+2)
	}
	for _, c := range rig.Fake.RangeCalled() {
		if c.Grid < c.Part.Len {
			t.Fatalf("range %v was read with the smaller grid %d", c.Part, c.Grid)
		}
	}
	chunkfixture.AssertMonotone(t, log.Items)
	last := log.Items[len(log.Items)-1]
	if last.Phase != transfercore.PhaseCleanup || last.Bytes != int64(len(content)) || last.Mode != transferengine.ModeChunked {
		t.Fatalf("last progress = %+v", last)
	}
	enginetest.ExpectContentFree(t, res, nil, content, rig.Root.Dir())
	for _, p := range log.Items {
		if strings.Contains(fmt.Sprintf("%+v", p), rig.Root.Dir()) {
			t.Fatalf("progress contains the local path: %+v", p)
		}
	}
}

func TestChunkedDownloadResumesFromPartsOfAPreviousProcess(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 32)
	rig.Put(content)
	seeded := []transferlink.Range{{Off: 0, Len: 512 << 10}, {Off: 512 << 10, Len: 512 << 10}}
	rig.Seed("big.bin", content, seeded...)

	// A new engine: empty link profile, as after a keeper restart.
	res, err, log := rig.Download(rig.FreshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	if n := rig.Fake.ReadCount(); n != 0 {
		t.Fatalf("a resumed transfer streamed the whole file (%d streams)", n)
	}
	attempts := rig.Fake.Ranges()
	if len(attempts) == 0 || attempts[0].Off != chunkfixture.ChunkMiB {
		t.Fatalf("first range read = %v, want it to start after the parts found on resume", attempts)
	}
	chunkfixture.AssertTiles(t, int64(len(content)), append(append([]transferlink.Range(nil), attempts...), seeded...))
	if res.Mode != transferengine.ModeChunked || res.Bytes != int64(len(content)) || res.ChunksDone != len(attempts)+2 {
		t.Fatalf("result = %+v", res)
	}
	if res.Attempts != len(attempts)+1 {
		t.Fatalf("attempts = %d, want %d part sessions and one assembly", res.Attempts, len(attempts))
	}
	chunkfixture.AssertMonotone(t, log.Items)
	var first *transferengine.Progress
	for i := range log.Items {
		if log.Items[i].Phase == transfercore.PhaseTransfer {
			first = &log.Items[i]
			break
		}
	}
	if first == nil || first.Bytes != chunkfixture.ChunkMiB || first.ChunksDone != 2 || first.Mode != transferengine.ModeChunked || first.ChunkBytes != 512<<10 {
		t.Fatalf("first transfer progress = %+v, want 1 MiB, 2 parts, chunk 512 KiB", first)
	}
}

func TestChunkedDownloadHalvesAfterADropAndMixesPartSizes(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 33)
	rig.Put(content)
	seed := transferlink.Range{Off: 0, Len: 600 << 10}
	rig.Seed("big.bin", content, seed)
	rig.Fake.SetRangeFault(func(n int, rg transferlink.Range) *testfixture.PartFailure {
		if n == 1 {
			return &testfixture.PartFailure{Cut: 100 << 10}
		}
		return nil
	})

	res, err, log := rig.Download(rig.FreshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	calls := rig.Fake.RangeCalled()
	// The size found on resume seeds the chunk size; the drop halves it, and
	// the next attempt resumes at the same gap with a smaller part.
	if len(calls) < 2 || calls[0].Part != (transferlink.Range{Off: 600 << 10, Len: 600 << 10}) ||
		calls[1].Part.Off != calls[0].Part.Off || calls[1].Part.Len >= calls[0].Part.Len {
		t.Fatalf("range reads = %v", calls)
	}
	// The dropped part is not in the coverage: the parts are the seed and every
	// successful read.
	var stored []transferlink.Range
	for _, c := range calls[1:] {
		stored = append(stored, c.Part)
	}
	all := append([]transferlink.Range{seed}, stored...)
	chunkfixture.AssertTiles(t, int64(len(content)), all)
	distinct := map[int64]bool{}
	for _, p := range all {
		distinct[p.Len] = true
	}
	if len(distinct) < 2 {
		t.Fatalf("parts of one size only: %v", all)
	}
	if res.ChunksDone != len(all) {
		t.Fatalf("chunks done = %d, want %d", res.ChunksDone, len(all))
	}
	chunkfixture.AssertMonotone(t, log.Items)
}

func TestChunkedDownloadSourceChangedMidway(t *testing.T) {
	mutations := map[string]func(rig *chunkfixture.DlRig, content []byte){
		"size": func(rig *chunkfixture.DlRig, content []byte) {
			rig.Put(append(append([]byte(nil), content...), 'x'))
		},
		"modification time": func(rig *chunkfixture.DlRig, content []byte) {
			rig.Fake.SetMTime(testfixture.DLMTime + 10)
		},
	}
	for name, mutate := range mutations {
		t.Run(strings.ReplaceAll(name, " ", "-"), func(t *testing.T) {
			rig := chunkfixture.NewDLRig(t)
			content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 34)
			rig.Put(content)
			rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
			// Look number 3 is the one before the second part.
			rig.Fake.SetOnStat(func(n int) {
				if n == 3 {
					mutate(rig, content)
				}
			})

			res, err, _ := rig.Download(rig.Engine, "big.bin", false)
			testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
			rig.AssertAbsent("big.bin")
			testfixture.NoStagingLeft(t, rig.Root.Dir())
			ranges := rig.Fake.Ranges()
			if len(ranges) != 1 {
				t.Fatalf("%d range reads ran, want 1 (the change is caught before part 2)", len(ranges))
			}
			if res.Mode != transferengine.ModeChunked || res.Bytes != ranges[0].Len {
				t.Fatalf("failed result = %+v", res)
			}
		})
	}
}

func TestChunkedDownloadSourceContentChangedBehindTheSameSizeAndTime(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 35)
	rig.Put(content)
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
	rig.Fake.SetOnStat(func(n int) {
		if n == 3 {
			changed := append([]byte(nil), content...)
			changed[len(changed)-1] ^= 0xff
			changed[2*chunkfixture.ChunkMiB] ^= 0xff
			rig.Put(changed)
		}
	})

	res, err, _ := rig.Download(rig.Engine, "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	rig.AssertAbsent("big.bin")
	testfixture.NoStagingLeft(t, rig.Root.Dir())
	// Only the whole-file hash can see this: every part was read first.
	if res.Mode != transferengine.ModeChunked || res.Bytes != int64(len(content)) {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestChunkedDownloadRemoteThatShrinksFailsIntegrity(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 36)
	rig.Put(content)
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
	rig.Fake.SetOnRange(func(n int, rg transferlink.Range) {
		if n == 2 {
			rig.Put(content[:rg.Off+100]) // most of the second range is no longer there
		}
	})

	_, err, _ := rig.Download(rig.Engine, "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	rig.AssertAbsent("big.bin")
	testfixture.NoStagingLeft(t, rig.Root.Dir())
}

func TestChunkedDownloadForeignStagingFallsBackToAStream(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 37)
	rig.Put(content)
	foreign := rig.StageDir("big.bin")
	chunkfixture.MakeForeignStage(t, foreign)
	before := chunkfixture.DlSnapshot(t, foreign)

	res, err, _ := rig.Download(rig.Engine, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	want := transferengine.Result{Kind: transferengine.KindFile, Files: 1, Bytes: int64(len(content)), SHA256: chunkfixture.SumHex(content)}
	if res != want {
		t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
	}
	got, readErr := os.ReadFile(rig.LocalPath("big.bin"))
	if readErr != nil || !bytes.Equal(got, content) {
		t.Fatal("the file is not downloaded byte-exact")
	}
	if n := len(rig.Fake.Ranges()); n != 0 {
		t.Fatalf("%d range reads ran next to a foreign staging object", n)
	}
	if after := chunkfixture.DlSnapshot(t, foreign); after != before {
		t.Fatal("the foreign object was touched")
	}
}

func TestChunkedDownloadForeignStagingAfterADropFailsRefused(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 38)
	rig.Put(content)
	foreign := rig.StageDir("big.bin")
	rig.Fake.SetReadFault(func(n int) *testfixture.PartFailure {
		if n == 1 {
			chunkfixture.MakeForeignStage(t, foreign) // appears after the lookup, before the chunked entry
			return &testfixture.PartFailure{Cut: chunkfixture.ChunkMiB}
		}
		return nil
	})

	_, err, _ := rig.Download(rig.Engine, "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassRefusedPath)
	rig.AssertAbsent("big.bin")
	if n := len(rig.Fake.Ranges()); n != 0 {
		t.Fatalf("%d range reads ran against a foreign staging object", n)
	}
	if got := chunkfixture.DlSnapshot(t, foreign); got != "keep keep\n" {
		t.Fatalf("the foreign object was touched: %q", got)
	}
	entries, readErr := os.ReadDir(rig.Root.Dir())
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("root holds %v (%v), want only the foreign object", entries, readErr)
	}
}

func TestChunkedDownloadAssemblyHashMismatchIsIntegrity(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 39)
	rig.Put(content)
	planted := map[transferlink.Range][]byte{
		{Off: 0, Len: chunkfixture.ChunkMiB}:                         chunkfixture.ChunkContent(chunkfixture.ChunkMiB, 99), // right length, wrong bytes
		{Off: chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB}:     content[chunkfixture.ChunkMiB : 2*chunkfixture.ChunkMiB],
		{Off: 2 * chunkfixture.ChunkMiB, Len: chunkfixture.ChunkMiB}: content[2*chunkfixture.ChunkMiB:],
	}
	rig.SeedWith("big.bin", sha256.Sum256(content), planted)

	res, err, _ := rig.Download(rig.FreshEngine(), "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	rig.AssertAbsent("big.bin")
	testfixture.NoStagingLeft(t, rig.Root.Dir())
	if n := len(rig.Fake.Ranges()); n != 0 {
		t.Fatalf("%d range reads ran for a complete staging", n)
	}
	if res.Mode != transferengine.ModeChunked || res.Bytes != int64(len(content)) {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestChunkedDownloadCancelRemovesStaging(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 40)
	rig.Put(content)
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rig.Fake.SetOnRange(func(n int, rg transferlink.Range) {
		if n == 2 {
			cancel()
		}
	})

	res, err := rig.Engine.Download(ctx, rig.Root, chunkfixture.DlRemote, "big.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassCancelled)
	rig.AssertAbsent("big.bin")
	testfixture.NoStagingLeft(t, rig.Root.Dir())
	ranges := rig.Fake.Ranges()
	if res.Mode != transferengine.ModeChunked || len(ranges) != 2 || res.Bytes != ranges[0].Len {
		t.Fatalf("failed result = %+v after %v", res, ranges)
	}
}

func TestChunkedDownloadGivesUpAfterEightAttemptsAndAnotherEngineResumes(t *testing.T) {
	rig := chunkfixture.NewDLRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 41)
	rig.Put(content)
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
	// Two parts get through, then every range read drops.
	rig.Fake.SetRangeFault(func(n int, rg transferlink.Range) *testfixture.PartFailure {
		if n >= 3 {
			return &testfixture.PartFailure{Cut: 100 << 10}
		}
		return nil
	})

	res, err, log := rig.Download(rig.Engine, "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassLinkUnstable)
	if err.Error() != transfercore.MsgLinkUnstable || err.Error() != "transfer link was too unstable to finish; a retry can resume" {
		t.Fatalf("message = %q", err.Error())
	}
	if n := len(rig.Fake.Ranges()); n != 2+transferlink.MaxNoProgress {
		t.Fatalf("%d range reads ran, want 2 stored and %d dropped", n, transferlink.MaxNoProgress)
	}
	rig.AssertAbsent("big.bin")
	kept := rig.Kept("big.bin", content)
	if len(kept) != 2 {
		t.Fatalf("staging holds %v, want the two stored parts", kept)
	}
	if res.Mode != transferengine.ModeChunked || res.Bytes != chunkfixture.SumLens(kept) || res.ChunksDone != 2 || res.Attempts != 1+2+transferlink.MaxNoProgress {
		t.Fatalf("failed result = %+v", res)
	}
	chunkfixture.AssertMonotone(t, log.Items)

	// The link works again; a brand-new engine continues from the parts on
	// disk with no profile and no second stream.
	rig.Fake.SetRangeFault(nil)
	resumedFrom := chunkfixture.SumLens(kept)
	res2, err2, _ := rig.Download(rig.FreshEngine(), "big.bin", false)
	if err2 != nil {
		t.Fatalf("resume: %v", err2)
	}
	rig.AssertDownloaded("big.bin", content)
	if n := rig.Fake.ReadCount(); n != 1 {
		t.Fatalf("the resume streamed again (%d streams)", n)
	}
	if first := rig.Fake.Ranges()[2+transferlink.MaxNoProgress]; first.Off != resumedFrom {
		t.Fatalf("resume started at %d, want %d", first.Off, resumedFrom)
	}
	if res2.Bytes != int64(len(content)) || res2.Mode != transferengine.ModeChunked {
		t.Fatalf("resumed result = %+v", res2)
	}
}

func TestChunkedDownloadSmallFilesAreNeverChunked(t *testing.T) {
	cases := []struct {
		size    int
		chunked bool
	}{
		{100 << 10, false},
		{2*int(transferlink.MinChunk) - 1, false},
		{2 * int(transferlink.MinChunk), true},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.size), func(t *testing.T) {
			rig := chunkfixture.NewDLRig(t)
			content := chunkfixture.ChunkContent(tc.size, 42)
			rig.Put(content)
			rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(int64(tc.size) / 2))

			res, err, _ := rig.Download(rig.Engine, "f.bin", false)
			if tc.chunked {
				if err != nil {
					t.Fatalf("Download: %v", err)
				}
				rig.AssertDownloaded("f.bin", content)
				if res.Mode != transferengine.ModeChunked || res.ChunksDone != 2 {
					t.Fatalf("result = %+v", res)
				}
				return
			}
			testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
			enginetest.ExpectNoResult(t, res)
			rig.AssertAbsent("f.bin")
			testfixture.NoStagingLeft(t, rig.Root.Dir())
			for _, call := range []string{"StatSource", "ReadRange"} {
				if n := rig.Fake.CallCount(call); n != 0 {
					t.Fatalf("%s ran %d times for a small file", call, n)
				}
			}
			if n := rig.Fake.ReadCount(); n != 1 {
				t.Fatalf("ReadFile ran %d times, want 1 (no retry)", n)
			}
		})
	}
}

func TestChunkedDownloadWithoutChunkCapabilitiesKeepsTheLegacyBehaviour(t *testing.T) {
	caps := map[string]transferremote.ChunkCaps{
		"no capabilities":    {},
		"no read primitive":  {Own: true, Read: transferremote.ReadNone, Mtime: transferremote.MtimeGNU, DF: true},
		"no stat flavour":    {Own: true, Read: transferremote.ReadDD, Mtime: transferremote.MtimeNone, DF: true},
		"no ownership check": {Own: false, Read: transferremote.ReadDD, Mtime: transferremote.MtimeGNU, DF: true},
	}
	for name, c := range caps {
		t.Run(strings.ReplaceAll(name, " ", "-"), func(t *testing.T) {
			rig := chunkfixture.NewDLRig(t)
			content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 43)
			rig.Put(content)
			rig.Fake.SetCaps(c)
			rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
			// Legacy behaviour touches no local staging of this kind at all: an
			// idle one stays where it is.
			stale := rig.StaleStage("big.bin", chunkfixture.ChunkContent(10, 1), 72*time.Hour, 9)

			res, err, _ := rig.Download(rig.Engine, "big.bin", false)
			testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
			enginetest.ExpectNoResult(t, res)
			rig.AssertAbsent("big.bin")
			for _, call := range []string{"StatSource", "ReadRange"} {
				if n := rig.Fake.CallCount(call); n != 0 {
					t.Fatalf("%s ran %d times on a target without download capabilities", call, n)
				}
			}
			if n := rig.Fake.ReadCount(); n != 1 {
				t.Fatalf("ReadFile ran %d times, want 1", n)
			}
			if _, statErr := os.Lstat(stale); statErr != nil {
				t.Fatalf("the idle staging was collected without chunk capabilities: %v", statErr)
			}
		})
	}
}
