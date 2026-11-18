package chunktest

import (
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/chunkfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// indexOfCall returns the index of the first call named name at or after from,
// or -1.
func indexOfCall(calls []string, name string, from int) int {
	for i := from; i < len(calls); i++ {
		if calls[i] == name {
			return i
		}
	}
	return -1
}

// The listing of a staging directory is where the remote layer removes leftover
// assembled.<rnd>.tmp files, so it has to precede every disk-space decision and
// every assembly after a dropped one.

func TestStagingIsListedBeforeTheDiskPreflight(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 31)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	rig.Fake.SeedStage(key, chunkfixture.SeedParts(content, transferlink.Range{Off: 0, Len: 512 << 10}))

	if _, err, _ := rig.Upload(rig.FreshEngine(), "big.bin", chunkfixture.ChunkDest, false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	calls := rig.Fake.CallsSnapshot()
	list, disk := indexOfCall(calls, "ListStaging", 0), indexOfCall(calls, "DiskAvailable", 0)
	if list < 0 || disk < 0 || list > disk {
		t.Fatalf("ListStaging at %d, DiskAvailable at %d in %v: the preflight must follow the listing", list, disk, calls)
	}
}

func TestStagingIsListedAgainAfterADroppedAssembly(t *testing.T) {
	rig := chunkfixture.NewChunkRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 32)
	rig.Write("big.bin", content)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
	rig.Fake.SetAssembleFault(func(n int) error {
		if n == 1 {
			return transferremote.LinkFailure()
		}
		return nil
	})

	if _, err, _ := rig.Upload(rig.Engine, "big.bin", chunkfixture.ChunkDest, false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	calls := rig.Fake.CallsSnapshot()
	first := indexOfCall(calls, "AssembleStaging", 0)
	second := indexOfCall(calls, "AssembleStaging", first+1)
	list := indexOfCall(calls, "ListStaging", first+1)
	if first < 0 || second < 0 || list < 0 || list > second {
		t.Fatalf("assemblies at %d and %d, listing between them at %d in %v: a dropped assembly's leftovers must be cleaned before the next one", first, second, list, calls)
	}
}
