package engine_test

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/chunkfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/engine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

func TestChunkedDownloadDiskPreflight(t *testing.T) {
	const size = 3 * chunkfixture.ChunkMiB
	cases := []struct {
		name      string
		avail     int64
		known     bool
		wantLimit bool
	}{
		{"short counting the parts found", 2*size - chunkfixture.ChunkMiB - 1, true, true},
		{"exactly enough counting the parts found", 2*size - chunkfixture.ChunkMiB, true, false},
		{"unknown answer skips the check", 1, false, false},
	}
	for _, tc := range cases {
		t.Run(strings.ReplaceAll(tc.name, " ", "-"), func(t *testing.T) {
			saved := *engine.DiskFree
			t.Cleanup(func() { *engine.DiskFree = saved })
			*engine.DiskFree = func(*transferlocal.ChunkStaging) (int64, bool) { return tc.avail, tc.known }

			rig := chunkfixture.NewDLRig(t)
			content := chunkfixture.ChunkContent(size, 54)
			rig.Put(content)
			rig.Seed("big.bin", content, transferlink.Range{Off: 0, Len: chunkfixture.ChunkMiB})

			res, err, _ := rig.Download(rig.FreshEngine(), "big.bin", false)
			if tc.wantLimit {
				testfixture.ExpectClass(t, err, transfercore.ClassLimit)
				if err.Error() != engine.MsgLocalDiskShort {
					t.Fatalf("message = %q", err.Error())
				}
				if n := len(rig.Fake.Ranges()); n != 0 {
					t.Fatalf("%d ranges were read before the disk refusal", n)
				}
				rig.AssertAbsent("big.bin")
				testfixture.NoStagingLeft(t, rig.Root.Dir())
				return
			}
			if err != nil {
				t.Fatalf("Download: %v", err)
			}
			if res.Bytes != size {
				t.Fatalf("result = %+v", res)
			}
			rig.AssertDownloaded("big.bin", content)
		})
	}
}

func TestChunkedDownloadPreflightLookFailuresDisableChunkingForTheCall(t *testing.T) {
	cases := map[string]struct {
		fault func(n int) error
		looks int
	}{
		"link failures": {func(n int) error { return transferremote.LinkFailure() }, engine.StatSourceTries},
		"remote status": {func(n int) error { return testfixture.StageErr(24) }, 1},
	}
	for name, tc := range cases {
		t.Run(strings.ReplaceAll(name, " ", "-"), func(t *testing.T) {
			rig := chunkfixture.NewDLRig(t)
			content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 59)
			rig.Put(content)
			rig.Fake.SetStatFault(tc.fault)

			res, err, _ := rig.Download(rig.Engine, "big.bin", false)
			if err != nil {
				t.Fatalf("Download: %v", err)
			}
			rig.AssertDownloaded("big.bin", content)
			want := engine.Result{Kind: engine.KindFile, Files: 1, Bytes: int64(len(content)), SHA256: chunkfixture.SumHex(content)}
			if res != want {
				t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
			}
			if n := rig.Fake.StatCount(); n != tc.looks {
				t.Fatalf("StatSource ran %d times, want %d", n, tc.looks)
			}
		})
	}
}

func TestChunkedUploadDiskPreflight(t *testing.T) {
	const size = 3 * chunkfixture.ChunkMiB
	cases := []struct {
		name      string
		resumed   bool // two 512 KiB parts are already in the staging
		avail     int64
		known     bool
		df        bool
		wantLimit bool
	}{
		{"short without parts", false, 2*size - 1, true, true, true},
		{"exactly enough without parts", false, 2 * size, true, true, false},
		{"short counting the parts found", true, 2*size - chunkfixture.ChunkMiB - 1, true, true, true},
		{"exactly enough counting the parts found", true, 2*size - chunkfixture.ChunkMiB, true, true, false},
		{"unknown answer skips the check", false, 1, false, true, false},
		{"no df capability skips the check", false, 1, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := chunkfixture.NewChunkRig(t)
			content := chunkfixture.ChunkContent(size, 7)
			rig.Write("big.bin", content)
			key := rig.Key("big.bin", chunkfixture.ChunkDest)
			if tc.resumed {
				rig.Fake.SeedStage(key, chunkfixture.SeedParts(content,
					transferlink.Range{Off: 0, Len: 512 << 10},
					transferlink.Range{Off: 512 << 10, Len: 512 << 10}))
			} else {
				rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
			}
			rig.Fake.SetDisk(tc.avail, tc.known)
			rig.Fake.SetCaps(transferremote.ChunkCaps{Own: true, Read: transferremote.ReadDD, Mtime: transferremote.MtimeGNU, DF: tc.df})

			res, err, _ := rig.Upload(rig.FreshEngine(), "big.bin", chunkfixture.ChunkDest, false)
			if tc.wantLimit {
				testfixture.ExpectClass(t, err, transfercore.ClassLimit)
				if err.Error() != engine.MsgDiskShort {
					t.Fatalf("message = %q", err.Error())
				}
				if n := len(rig.Fake.PartAttempts()); n != 0 {
					t.Fatalf("%d parts were sent before the disk refusal", n)
				}
				chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
				chunkfixture.AssertCleanRemote(t, rig.Fake)
				return
			}
			if err != nil {
				t.Fatalf("Upload: %v", err)
			}
			if res.Bytes != size {
				t.Fatalf("result = %+v", res)
			}
			chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
		})
	}
}
