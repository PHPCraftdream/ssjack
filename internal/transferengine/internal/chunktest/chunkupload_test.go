package chunktest

import (
	"bytes"
	"context"
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

func TestChunkedUploadStreamDropThenChunkedCompletion(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 1)
	rig.Write("big.bin", content)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))

	res, err, log := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	stored := rig.Fake.StoredParts()
	chunkfixture.AssertTiles(t, int64(len(content)), stored)
	if res.Kind != transferengine.KindFile || res.Files != 1 || res.Bytes != int64(len(content)) || res.SHA256 != chunkfixture.SumHex(content) {
		t.Fatalf("result = %+v", res)
	}
	if res.Mode != transferengine.ModeChunked || res.ChunksDone != len(stored) || res.ChunksTotal != len(stored) {
		t.Fatalf("chunk telemetry = %+v, want chunked with %d parts", res, len(stored))
	}
	// One stream, one session per part, one assembly.
	if res.Attempts != 1+len(stored)+1 {
		t.Fatalf("attempts = %d, want %d", res.Attempts, 1+len(stored)+1)
	}
	if res.BytesPerSecond <= 0 || res.ChunkBytes <= 0 {
		t.Fatalf("telemetry has no speed or chunk size: %+v", res)
	}
	if n := rig.Fake.CallCount("WriteFile"); n != 1 {
		t.Fatalf("WriteFile ran %d times, want the one dropped stream", n)
	}
	if n := rig.Fake.CallCount("AssembleStaging"); n != 1 {
		t.Fatalf("AssembleStaging ran %d times", n)
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

func TestChunkedUploadResumesFromPartsOfAPreviousProcess(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 2)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	rig.Fake.SeedStage(key, chunkfixture.SeedParts(content,
		transferlink.Range{Off: 0, Len: 512 << 10},
		transferlink.Range{Off: 512 << 10, Len: 512 << 10},
	))

	// A new engine: empty link profile, as after a keeper restart.
	res, err, log := rig.Upload(rig.FreshEngine(), "big.bin", chunkfixture.ChunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	if n := rig.Fake.CallCount("WriteFile"); n != 0 {
		t.Fatalf("a resumed transfer streamed the whole file (%d streams)", n)
	}
	attempts := rig.Fake.PartAttempts()
	if len(attempts) == 0 || attempts[0].Off != chunkfixture.ChunkMiB {
		t.Fatalf("first part attempt = %v, want it to start after the parts found on resume", attempts)
	}
	chunkfixture.AssertTiles(t, int64(len(content)), append(rig.Fake.StoredParts(),
		transferlink.Range{Off: 0, Len: 512 << 10},
		transferlink.Range{Off: 512 << 10, Len: 512 << 10}))
	if res.Mode != transferengine.ModeChunked || res.Bytes != int64(len(content)) || res.ChunksDone != len(attempts)+2 {
		t.Fatalf("result = %+v", res)
	}
	if res.Attempts != len(attempts)+1 {
		t.Fatalf("attempts = %d, want %d part sessions and one assembly", res.Attempts, len(attempts))
	}
	// The bytes found on resume count at once, never go back, and the chunk
	// size starts from the largest part found.
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

func TestChunkedUploadHalvesAfterADropAndMixesPartSizes(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 3)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	seed := transferlink.Range{Off: 0, Len: 600 << 10}
	rig.Fake.SeedStage(key, chunkfixture.SeedParts(content, seed))
	rig.Fake.SetPartFault(func(n int, rg transferlink.Range) *testfixture.PartFailure {
		if n == 1 {
			return &testfixture.PartFailure{Cut: 100 << 10}
		}
		return nil
	})

	res, err, log := rig.Upload(rig.FreshEngine(), "big.bin", chunkfixture.ChunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	attempts := rig.Fake.PartAttempts()
	// The size found on resume seeds the chunk size; the drop halves it, down
	// to the 256 KiB floor, and the next attempt resumes at the same gap.
	if len(attempts) < 2 || attempts[0] != (transferlink.Range{Off: 600 << 10, Len: 600 << 10}) ||
		attempts[1] != (transferlink.Range{Off: 600 << 10, Len: transferlink.MinChunk}) {
		t.Fatalf("part attempts = %v", attempts)
	}
	all := append([]transferlink.Range{seed}, rig.Fake.StoredParts()...)
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

func TestChunkedUploadSourceChangedMidway(t *testing.T) {
	mutations := map[string]func(t *testing.T, path string){
		"appended bytes": func(t *testing.T, path string) {
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				t.Errorf("open source: %v", err)
				return
			}
			if _, err := file.WriteString("appended"); err != nil {
				t.Errorf("append: %v", err)
			}
			if err := file.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		},
		"modification time": func(t *testing.T, path string) {
			later := time.Now().Add(time.Hour)
			if err := os.Chtimes(path, later, later); err != nil {
				t.Errorf("chtimes: %v", err)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			rig := chunkfixture.NewChunkRig(t)
			content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 4)
			path := rig.Write("big.bin", content)
			rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
			rig.Fake.SetOnPart(func(n int, rg transferlink.Range) {
				if n == 2 {
					mutate(t, path)
				}
			})

			res, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
			testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
			chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
			chunkfixture.AssertCleanRemote(t, rig.Fake)
			if n := len(rig.Fake.PartAttempts()); n != 2 {
				t.Fatalf("%d part sessions ran, want 2 (the change is caught before part 3)", n)
			}
			if res.Mode != transferengine.ModeChunked || res.Bytes != chunkfixture.SumLens(rig.Fake.StoredParts()) {
				t.Fatalf("failed result = %+v", res)
			}
			if n := rig.Fake.CallCount("RemoveChunkStaging"); n != 1 {
				t.Fatalf("staging removal ran %d times, want 1", n)
			}
		})
	}
}

func TestChunkedUploadForeignStagingFallsBackToAStream(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 5)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	rig.Fake.SetForeign(key, true)

	res, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	want := transferengine.Result{Kind: transferengine.KindFile, Files: 1, Bytes: int64(len(content)), SHA256: chunkfixture.SumHex(content)}
	if res != want {
		t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	for _, call := range []string{"EnsureStaging", "UploadPart", "RemoveChunkStaging", "AssembleStaging"} {
		if n := rig.Fake.CallCount(call); n != 0 {
			t.Fatalf("%s ran %d times next to a foreign staging object", call, n)
		}
	}
	if !rig.Fake.IsForeign(key) {
		t.Fatal("the foreign object was touched")
	}
}

func TestChunkedUploadForeignStagingAfterADropFailsRemote(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 6)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	rig.Fake.SetEnsureForeign(key, true)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))

	_, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
	testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
	chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	for _, call := range []string{"UploadPart", "RemoveChunkStaging"} {
		if n := rig.Fake.CallCount(call); n != 0 {
			t.Fatalf("%s ran %d times against a foreign staging object", call, n)
		}
	}
}

func TestChunkedUploadRechecksTheDiskAfterAPartFailure(t *testing.T) {
	for _, full := range []bool{true, false} {
		t.Run(fmt.Sprintf("disk full %v", full), func(t *testing.T) {
			rig := chunkfixture.NewChunkRig(t)
			content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 8)
			rig.Write("big.bin", content)
			rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
			rig.Fake.SetOnPart(func(n int, rg transferlink.Range) {
				if n == 2 && full {
					rig.Fake.SetDisk(1, true)
				}
			})
			rig.Fake.SetPartFault(func(n int, rg transferlink.Range) *testfixture.PartFailure {
				if n == 2 {
					return &testfixture.PartFailure{Cut: 1000, Err: testfixture.StageErr(24)}
				}
				return nil
			})

			_, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
			if full {
				testfixture.ExpectClass(t, err, transfercore.ClassLimit)
			} else {
				testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
			}
			if n := len(rig.Fake.PartAttempts()); n != 2 {
				t.Fatalf("%d part sessions ran, want 2 (a remote status is not retried)", n)
			}
			chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
			chunkfixture.AssertCleanRemote(t, rig.Fake)
		})
	}
}

func TestChunkedUploadAssemblyHashMismatchIsIntegrity(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 9)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	planted := map[transferlink.Range][]byte{
		{Off: 0, Len: 512 << 10}:         chunkfixture.ChunkContent(512<<10, 99), // right length, wrong bytes
		{Off: 512 << 10, Len: 512 << 10}: content[512<<10 : chunkfixture.ChunkMiB],
	}
	rig.Fake.SeedStage(key, planted)

	res, err, _ := rig.Upload(rig.FreshEngine(), "big.bin", chunkfixture.ChunkDest, false)
	testfixture.ExpectClass(t, err, transfercore.ClassIntegrity)
	chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	if n := rig.Fake.CallCount("PublishFile"); n != 0 {
		t.Fatalf("PublishFile ran %d times after a hash mismatch", n)
	}
	if res.Mode != transferengine.ModeChunked {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestChunkedUploadCancelRemovesStaging(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 10)
	rig.Write("big.bin", content)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rig.Fake.SetOnPart(func(n int, rg transferlink.Range) {
		if n == 2 {
			cancel()
		}
	})

	_, err := rig.Engine.Upload(ctx, rig.Root, "big.bin", chunkfixture.ChunkDest, false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassCancelled)
	chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	if n := rig.Fake.CallCount("RemoveChunkStaging"); n != 1 {
		t.Fatalf("staging removal ran %d times after cancellation, want 1", n)
	}
}

func TestChunkedUploadGivesUpAfterEightAttemptsAndAnotherEngineResumes(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 11)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
	// Two parts get through, then every part session drops.
	rig.Fake.SetPartFault(func(n int, rg transferlink.Range) *testfixture.PartFailure {
		if n >= 3 {
			return &testfixture.PartFailure{Cut: 100 << 10}
		}
		return nil
	})

	res, err, log := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
	testfixture.ExpectClass(t, err, transfercore.ClassLinkUnstable)
	if err.Error() != transfercore.MsgLinkUnstable || err.Error() != "transfer link was too unstable to finish; a retry can resume" {
		t.Fatalf("message = %q", err.Error())
	}
	if n := len(rig.Fake.PartAttempts()); n != 2+transferlink.MaxNoProgress {
		t.Fatalf("%d part sessions ran, want 2 stored and %d dropped", n, transferlink.MaxNoProgress)
	}
	kept := rig.Fake.StageParts(key)
	if len(kept) != 2 || chunkfixture.SumLens(kept) != chunkfixture.SumLens(rig.Fake.StoredParts()) {
		t.Fatalf("staging holds %v, want the two stored parts", kept)
	}
	if n := rig.Fake.CallCount("RemoveChunkStaging"); n != 0 {
		t.Fatalf("link_unstable removed its staging (%d removals)", n)
	}
	chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
	if res.Mode != transferengine.ModeChunked || res.Bytes != chunkfixture.SumLens(kept) || res.ChunksDone != 2 || res.Attempts != 1+2+transferlink.MaxNoProgress {
		t.Fatalf("failed result = %+v", res)
	}
	chunkfixture.AssertMonotone(t, log.Items)

	// The link works again; a brand-new engine continues from the parts on
	// the remote side with no profile and no second stream.
	rig.Fake.SetPartFault(nil)
	resumedFrom := chunkfixture.SumLens(kept)
	res2, err2, _ := rig.Upload(rig.FreshEngine(), "big.bin", chunkfixture.ChunkDest, false)
	if err2 != nil {
		t.Fatalf("resume: %v", err2)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	if n := rig.Fake.CallCount("WriteFile"); n != 1 {
		t.Fatalf("the resume streamed again (%d streams)", n)
	}
	attempts := rig.Fake.PartAttempts()
	if first := attempts[2+transferlink.MaxNoProgress]; first.Off != resumedFrom {
		t.Fatalf("resume started at %d, want %d", first.Off, resumedFrom)
	}
	if res2.Bytes != int64(len(content)) || res2.Mode != transferengine.ModeChunked {
		t.Fatalf("resumed result = %+v", res2)
	}
}

func TestChunkedUploadSmallFilesAreNeverChunked(t *testing.T) {
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
			rig := chunkfixture.NewChunkRig(t)
			content := chunkfixture.ChunkContent(tc.size, 12)
			rig.Write("f.bin", content)
			rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(int64(tc.size) / 2))

			res, err, _ := rig.Upload(rig.Engine, "f.bin", chunkfixture.ChunkDest, false)
			if tc.chunked {
				if err != nil {
					t.Fatalf("Upload: %v", err)
				}
				chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
				if res.Mode != transferengine.ModeChunked || res.ChunksDone != 2 {
					t.Fatalf("result = %+v", res)
				}
				return
			}
			testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
			enginetest.ExpectNoResult(t, res)
			chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
			chunkfixture.AssertCleanRemote(t, rig.Fake)
			for _, call := range []string{"ListStaging", "EnsureStaging", "UploadPart", "RemoveChunkStaging"} {
				if n := rig.Fake.CallCount(call); n != 0 {
					t.Fatalf("%s ran %d times for a small file", call, n)
				}
			}
			if n := rig.Fake.CallCount("WriteFile"); n != 1 {
				t.Fatalf("WriteFile ran %d times, want 1 (no retry)", n)
			}
		})
	}
}

func TestChunkedUploadWithoutChunkCapabilitiesKeepsTheLegacyBehaviour(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 13)
	rig.Write("big.bin", content)
	rig.Fake.SetCaps(transferremote.ChunkCaps{})
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))

	res, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
	testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
	enginetest.ExpectNoResult(t, res)
	chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	for _, call := range []string{"CollectStaging", "ListStaging", "EnsureStaging", "UploadPart", "RemoveChunkStaging", "DiskAvailable"} {
		if n := rig.Fake.CallCount(call); n != 0 {
			t.Fatalf("%s ran %d times on a target without chunk capabilities", call, n)
		}
	}
	if n := rig.Fake.CallCount("WriteFile"); n != 1 {
		t.Fatalf("WriteFile ran %d times, want 1", n)
	}
}

func TestChunkedUploadNonLinkFailureIsNotRetried(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 14)
	rig.Write("big.bin", content)
	rig.Fake.SetStreamFault(func(n int) *testfixture.PartFailure {
		return &testfixture.PartFailure{Cut: chunkfixture.ChunkMiB, Err: testfixture.StageErr(24)}
	})

	res, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
	testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
	enginetest.ExpectNoResult(t, res)
	chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	if n := rig.Fake.CallCount("WriteFile"); n != 1 {
		t.Fatalf("WriteFile ran %d times, want 1", n)
	}
	for _, call := range []string{"EnsureStaging", "UploadPart"} {
		if n := rig.Fake.CallCount(call); n != 0 {
			t.Fatalf("%s ran %d times after a remote exit status", call, n)
		}
	}
}

func TestChunkedUploadProfileCarriesOverToTheNextJob(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 15)
	rig.Write("one.bin", content)
	rig.Write("two.bin", content)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))

	if _, err, _ := rig.Upload(rig.Engine, "one.bin", "/data/one.bin", false); err != nil {
		t.Fatalf("first job: %v", err)
	}
	streams := rig.Fake.CallCount("WriteFile")
	res, err, _ := rig.Upload(rig.Engine, "two.bin", "/data/two.bin", false)
	if err != nil {
		t.Fatalf("second job: %v", err)
	}
	if n := rig.Fake.CallCount("WriteFile"); n != streams {
		t.Fatalf("the second job streamed (%d streams, was %d): it ignored the profile", n, streams)
	}
	// No stream: one session per part, one assembly.
	if res.Mode != transferengine.ModeChunked || res.Attempts != res.ChunksDone+1 {
		t.Fatalf("second job result = %+v", res)
	}
	chunkfixture.AssertPublished(t, rig.Fake, "/data/two.bin", content)
}

func TestChunkedUploadPublicationSemanticsMatchTheStream(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("overwrite %v", overwrite), func(t *testing.T) {
			rig := chunkfixture.NewChunkRig(t)
			content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 16)
			rig.Write("big.bin", content)
			rig.Fake.Put(chunkfixture.ChunkDest, []byte("old content"))
			rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))

			_, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, overwrite)
			if overwrite {
				if err != nil {
					t.Fatalf("Upload: %v", err)
				}
				chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
			} else {
				testfixture.ExpectClass(t, err, transfercore.ClassExists)
				got, _ := rig.Fake.Get(chunkfixture.ChunkDest)
				if !bytes.Equal(got, []byte("old content")) {
					t.Fatal("the existing destination was modified")
				}
			}
			chunkfixture.AssertCleanRemote(t, rig.Fake)
		})
	}
}

func TestChunkedUploadCollectsStaleStagingAtPreflightAndIgnoresItsFailure(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 17)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	rig.Fake.SetGCErr(transferremote.LinkFailure())

	if _, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	gcLog := rig.Fake.GCLog()
	if len(gcLog) != 1 || gcLog[0] != (testfixture.GCCall{Parent: "/data", Exclude: key}) {
		t.Fatalf("garbage collection calls = %+v", gcLog)
	}
}

func TestChunkedUploadRemovesIgnoredEntriesFoundOnResume(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 18)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	seeded := chunkfixture.SeedParts(content, transferlink.Range{Off: 0, Len: 512 << 10})
	seeded[transferlink.Range{Off: 512 << 10, Len: 512 << 10}] = []byte("a lying size") // name says 512 KiB
	rig.Fake.SeedStage(key, seeded)

	if _, err, _ := rig.Upload(rig.FreshEngine(), "big.bin", chunkfixture.ChunkDest, false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	removed := rig.Fake.RemovedEntries()
	if len(removed) != 1 || len(removed[0]) != 1 || removed[0][0] != "part-524288-524288" {
		t.Fatalf("removed entries = %v", removed)
	}
	if first := rig.Fake.PartAttempts()[0]; first.Off != 512<<10 {
		t.Fatalf("first part = %v, want the lying entry's range to be sent again", first)
	}
}

func TestChunkedUploadCorruptStagingRestartsOnceOnly(t *testing.T) {
	t.Run("once", func(t *testing.T) {
		rig := chunkfixture.NewChunkRig(t)
		content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 19)
		rig.Write("big.bin", content)
		rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
		rig.Fake.SetOverflowList(2, true) // 1 is the lookup, 2 the first resync

		if _, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false); err != nil {
			t.Fatalf("Upload: %v", err)
		}
		chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
		chunkfixture.AssertCleanRemote(t, rig.Fake)
		if n := rig.Fake.CallCount("RemoveChunkStaging"); n != 2 {
			t.Fatalf("staging removals = %d, want the restart and the final one", n)
		}
	})
	t.Run("twice", func(t *testing.T) {
		rig := chunkfixture.NewChunkRig(t)
		content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 20)
		rig.Write("big.bin", content)
		rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
		rig.Fake.SetOverflowList(2, true)
		rig.Fake.SetOverflowList(3, true)

		_, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
		testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
		chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
		chunkfixture.AssertCleanRemote(t, rig.Fake)
	})
}

func TestChunkedUploadVanishedStagingRestartsFromZeroWithMonotoneBytes(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 21)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
	rig.Fake.SetOnPart(func(n int, rg transferlink.Range) {
		if n == 3 {
			rig.Fake.DropStage(key) // someone removed it after two parts
		}
	})

	_, err, log := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	chunkfixture.AssertMonotone(t, log.Items)
	if n := rig.Fake.CallCount("EnsureStaging"); n != 2 {
		t.Fatalf("EnsureStaging ran %d times, want the entry and one re-creation", n)
	}
}

func TestChunkedUploadAssemblyDropKeepsThePartsAndReassembles(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 22)
	rig.Write("big.bin", content)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
	rig.Fake.SetAssembleFault(func(n int) error {
		if n == 1 {
			return transferremote.LinkFailure()
		}
		return nil
	})

	res, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	if n := rig.Fake.CallCount("AssembleStaging"); n != 2 {
		t.Fatalf("AssembleStaging ran %d times, want 2", n)
	}
	stored := rig.Fake.StoredParts()
	if n := len(rig.Fake.PartAttempts()); n != len(stored) {
		t.Fatalf("%d part sessions for %d parts: a part was sent again after the assembly drop", n, len(stored))
	}
	if res.Attempts != 1+len(stored)+2 {
		t.Fatalf("attempts = %d, want %d", res.Attempts, 1+len(stored)+2)
	}
}

func TestChunkedUploadPublicationDropReassemblesAndPublishesOnce(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 23)
	rig.Write("big.bin", content)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
	rig.Fake.SetPublishFault(func(n int) error {
		if n == 1 {
			return transferremote.LinkFailure()
		}
		return nil
	})

	if _, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	if n := rig.Fake.PublishCount(); n != 1 {
		t.Fatalf("published %d times, want once", n)
	}
	if n := rig.Fake.CallCount("AssembleStaging"); n != 2 {
		t.Fatalf("AssembleStaging ran %d times, want 2", n)
	}
}

func TestChunkedUploadForeignAtEnsureBeforeAnyStreamFallsBack(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 24)
	rig.Write("one.bin", content)
	rig.Write("two.bin", content)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
	if _, err, _ := rig.Upload(rig.Engine, "one.bin", "/data/one.bin", false); err != nil {
		t.Fatalf("first job: %v", err)
	}
	parts := len(rig.Fake.PartAttempts())
	// The profile now sends the next job straight to chunked mode, where the
	// staging name turns out to be foreign before any stream was tried.
	rig.Fake.SetEnsureForeign(rig.Key("two.bin", "/data/two.bin"), true)

	res, err, _ := rig.Upload(rig.Engine, "two.bin", "/data/two.bin", false)
	if err != nil {
		t.Fatalf("second job: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, "/data/two.bin", content)
	if n := rig.Fake.CallCount("WriteFile"); n != 2 {
		t.Fatalf("WriteFile ran %d times, want the dropped stream and the fallback stream", n)
	}
	if n := len(rig.Fake.PartAttempts()); n != parts {
		t.Fatalf("the second job sent parts (%d, was %d)", n, parts)
	}
	if res.Mode != transferengine.ModeStream || res.Attempts != 1 || res.ChunksDone != 0 {
		t.Fatalf("second job result = %+v", res)
	}
}
