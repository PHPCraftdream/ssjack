package transferengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

const (
	chunkMiB  = 1 << 20
	chunkDest = "/data/out.bin"
)

// chunkRig is one engine over the in-memory chunk remote with a virtual
// clock: no test here sleeps or waits on a real timer.
type chunkRig struct {
	t      *testing.T
	clock  *vclock
	fake   *fakeChunkRemote
	engine *Engine
	root   *transferlocal.Root
}

func newChunkRig(t *testing.T) *chunkRig {
	t.Helper()
	clock := newVClock()
	rig := &chunkRig{t: t, clock: clock, fake: newFakeChunkRemote(clock), root: testRoot(t)}
	rig.engine = rig.freshEngine()
	return rig
}

// freshEngine returns an engine of the same target with an empty link
// profile: a new keeper process.
func (r *chunkRig) freshEngine() *Engine {
	r.t.Helper()
	profile := transferlink.NewProfile(transferlink.Config{Now: r.clock.Now})
	engine, err := NewWithOptions(r.fake, transfercore.DefaultLimits(), Options{Target: "t1", Profile: profile, Now: r.clock.Now})
	if err != nil {
		r.t.Fatalf("NewWithOptions: %v", err)
	}
	return engine
}

func (r *chunkRig) write(rel string, content []byte) string {
	return writeLocalFile(r.t, r.root, rel, content)
}

// key is the staging key the engine derives for the current state of rel.
func (r *chunkRig) key(rel, remote string) string {
	r.t.Helper()
	info, err := os.Stat(filepath.Join(r.root.Dir(), filepath.FromSlash(rel)))
	if err != nil {
		r.t.Fatal(err)
	}
	return transferremote.StagingKey("t1", remote, rel, strconv.FormatInt(info.Size(), 10), strconv.FormatInt(info.ModTime().UnixNano(), 10))
}

func (r *chunkRig) upload(engine *Engine, rel, remote string, overwrite bool) (Result, error, *progressLog) {
	log := &progressLog{}
	res, err := engine.Upload(context.Background(), r.root, rel, remote, overwrite, log.add)
	return res, err, log
}

type progressLog struct{ items []Progress }

func (p *progressLog) add(pr Progress) { p.items = append(p.items, pr) }

func chunkContent(n int, seed byte) []byte {
	out := make([]byte, n)
	state := uint32(seed)*2654435761 + 1
	for i := range out {
		state = state*1664525 + 1013904223
		out[i] = byte(state >> 24)
	}
	return out
}

func sumHex(content []byte) string {
	s := sha256.Sum256(content)
	return hex.EncodeToString(s[:])
}

func assertMonotone(t *testing.T, items []Progress) {
	t.Helper()
	var last int64
	for i, p := range items {
		if p.Bytes < last {
			t.Fatalf("progress %d (%s) went back from %d to %d bytes", i, p.Phase, last, p.Bytes)
		}
		last = p.Bytes
	}
}

func assertTiles(t *testing.T, size int64, parts []transferlink.Range) {
	t.Helper()
	if err := transferlink.ValidateTiling(size, parts); err != nil {
		t.Fatalf("parts do not tile the file: %v (%v)", err, parts)
	}
}

func assertPublished(t *testing.T, fake *fakeChunkRemote, dest string, want []byte) {
	t.Helper()
	got, ok := fake.get(dest)
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("%s is not published byte-exact (present=%v)", dest, ok)
	}
}

func assertNotPublished(t *testing.T, fake *fakeChunkRemote, dest string) {
	t.Helper()
	if _, ok := fake.get(dest); ok {
		t.Fatalf("%s was published", dest)
	}
	if fake.publishCount() != 0 {
		t.Fatalf("publication recorded %d times", fake.publishCount())
	}
}

// assertCleanRemote requires neither a chunk staging nor a stream staging.
func assertCleanRemote(t *testing.T, fake *fakeChunkRemote) {
	t.Helper()
	if n := fake.stageCount(); n != 0 {
		t.Fatalf("%d chunk staging directories left behind", n)
	}
	if n := fake.stagingCount(); n != 0 {
		t.Fatalf("%d stream staging directories left behind", n)
	}
}

// dropFirstStream scripts the first whole-stream attempt to drop after cut
// bytes; later streams run normally.
func dropFirstStream(cut int64) func(int) *partFailure {
	return func(n int) *partFailure {
		if n == 1 {
			return &partFailure{cut: cut}
		}
		return nil
	}
}

func sumLens(parts []transferlink.Range) int64 {
	var n int64
	for _, p := range parts {
		n += p.Len
	}
	return n
}

func seedParts(content []byte, ranges ...transferlink.Range) map[transferlink.Range][]byte {
	out := map[transferlink.Range][]byte{}
	for _, r := range ranges {
		out[r] = content[r.Off:r.End()]
	}
	return out
}

func TestChunkedUploadStreamDropThenChunkedCompletion(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 1)
	rig.write("big.bin", content)
	rig.fake.streamFault = dropFirstStream(chunkMiB)

	res, err, log := rig.upload(rig.engine, "big.bin", chunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	assertCleanRemote(t, rig.fake)
	stored := rig.fake.storedParts()
	assertTiles(t, int64(len(content)), stored)
	if res.Kind != KindFile || res.Files != 1 || res.Bytes != int64(len(content)) || res.SHA256 != sumHex(content) {
		t.Fatalf("result = %+v", res)
	}
	if res.Mode != ModeChunked || res.ChunksDone != len(stored) || res.ChunksTotal != len(stored) {
		t.Fatalf("chunk telemetry = %+v, want chunked with %d parts", res, len(stored))
	}
	// One stream, one session per part, one assembly.
	if res.Attempts != 1+len(stored)+1 {
		t.Fatalf("attempts = %d, want %d", res.Attempts, 1+len(stored)+1)
	}
	if res.BytesPerSecond <= 0 || res.ChunkBytes <= 0 {
		t.Fatalf("telemetry has no speed or chunk size: %+v", res)
	}
	if n := rig.fake.callCount("WriteFile"); n != 1 {
		t.Fatalf("WriteFile ran %d times, want the one dropped stream", n)
	}
	if n := rig.fake.callCount("AssembleStaging"); n != 1 {
		t.Fatalf("AssembleStaging ran %d times", n)
	}
	assertMonotone(t, log.items)
	last := log.items[len(log.items)-1]
	if last.Phase != transfercore.PhaseCleanup || last.Bytes != int64(len(content)) || last.Mode != ModeChunked {
		t.Fatalf("last progress = %+v", last)
	}
	expectContentFree(t, res, nil, content, rig.root.Dir())
	for _, p := range log.items {
		if strings.Contains(fmt.Sprintf("%+v", p), rig.root.Dir()) {
			t.Fatalf("progress contains the local path: %+v", p)
		}
	}
}

func TestChunkedUploadResumesFromPartsOfAPreviousProcess(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 2)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	rig.fake.seedStage(key, seedParts(content,
		transferlink.Range{Off: 0, Len: 512 << 10},
		transferlink.Range{Off: 512 << 10, Len: 512 << 10},
	))

	// A new engine: empty link profile, as after a keeper restart.
	res, err, log := rig.upload(rig.freshEngine(), "big.bin", chunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	assertCleanRemote(t, rig.fake)
	if n := rig.fake.callCount("WriteFile"); n != 0 {
		t.Fatalf("a resumed transfer streamed the whole file (%d streams)", n)
	}
	attempts := rig.fake.partAttempts()
	if len(attempts) == 0 || attempts[0].Off != chunkMiB {
		t.Fatalf("first part attempt = %v, want it to start after the parts found on resume", attempts)
	}
	assertTiles(t, int64(len(content)), append(rig.fake.storedParts(),
		transferlink.Range{Off: 0, Len: 512 << 10},
		transferlink.Range{Off: 512 << 10, Len: 512 << 10}))
	if res.Mode != ModeChunked || res.Bytes != int64(len(content)) || res.ChunksDone != len(attempts)+2 {
		t.Fatalf("result = %+v", res)
	}
	if res.Attempts != len(attempts)+1 {
		t.Fatalf("attempts = %d, want %d part sessions and one assembly", res.Attempts, len(attempts))
	}
	// The bytes found on resume count at once, never go back, and the chunk
	// size starts from the largest part found.
	assertMonotone(t, log.items)
	var first *Progress
	for i := range log.items {
		if log.items[i].Phase == transfercore.PhaseTransfer {
			first = &log.items[i]
			break
		}
	}
	if first == nil || first.Bytes != chunkMiB || first.ChunksDone != 2 || first.Mode != ModeChunked || first.ChunkBytes != 512<<10 {
		t.Fatalf("first transfer progress = %+v, want 1 MiB, 2 parts, chunk 512 KiB", first)
	}
}

func TestChunkedUploadHalvesAfterADropAndMixesPartSizes(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 3)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	seed := transferlink.Range{Off: 0, Len: 600 << 10}
	rig.fake.seedStage(key, seedParts(content, seed))
	rig.fake.partFault = func(n int, rg transferlink.Range) *partFailure {
		if n == 1 {
			return &partFailure{cut: 100 << 10}
		}
		return nil
	}

	res, err, log := rig.upload(rig.freshEngine(), "big.bin", chunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	attempts := rig.fake.partAttempts()
	// The size found on resume seeds the chunk size; the drop halves it, down
	// to the 256 KiB floor, and the next attempt resumes at the same gap.
	if len(attempts) < 2 || attempts[0] != (transferlink.Range{Off: 600 << 10, Len: 600 << 10}) ||
		attempts[1] != (transferlink.Range{Off: 600 << 10, Len: transferlink.MinChunk}) {
		t.Fatalf("part attempts = %v", attempts)
	}
	all := append([]transferlink.Range{seed}, rig.fake.storedParts()...)
	assertTiles(t, int64(len(content)), all)
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
	assertMonotone(t, log.items)
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
			rig := newChunkRig(t)
			content := chunkContent(3*chunkMiB, 4)
			path := rig.write("big.bin", content)
			rig.fake.streamFault = dropFirstStream(chunkMiB)
			rig.fake.onPart = func(n int, rg transferlink.Range) {
				if n == 2 {
					mutate(t, path)
				}
			}

			res, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false)
			expectClass(t, err, transfercore.ClassIntegrity)
			assertNotPublished(t, rig.fake, chunkDest)
			assertCleanRemote(t, rig.fake)
			if n := len(rig.fake.partAttempts()); n != 2 {
				t.Fatalf("%d part sessions ran, want 2 (the change is caught before part 3)", n)
			}
			if res.Mode != ModeChunked || res.Bytes != sumLens(rig.fake.storedParts()) {
				t.Fatalf("failed result = %+v", res)
			}
			if n := rig.fake.callCount("RemoveChunkStaging"); n != 1 {
				t.Fatalf("staging removal ran %d times, want 1", n)
			}
		})
	}
}

func TestChunkedUploadForeignStagingFallsBackToAStream(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 5)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	rig.fake.foreign[key] = true

	res, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	want := Result{Kind: KindFile, Files: 1, Bytes: int64(len(content)), SHA256: sumHex(content)}
	if res != want {
		t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	for _, call := range []string{"EnsureStaging", "UploadPart", "RemoveChunkStaging", "AssembleStaging"} {
		if n := rig.fake.callCount(call); n != 0 {
			t.Fatalf("%s ran %d times next to a foreign staging object", call, n)
		}
	}
	if !rig.fake.foreign[key] {
		t.Fatal("the foreign object was touched")
	}
}

func TestChunkedUploadForeignStagingAfterADropFailsRemote(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 6)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	rig.fake.ensureForeign[key] = true
	rig.fake.streamFault = dropFirstStream(chunkMiB)

	_, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false)
	expectClass(t, err, transfercore.ClassRemoteFailed)
	assertNotPublished(t, rig.fake, chunkDest)
	assertCleanRemote(t, rig.fake)
	for _, call := range []string{"UploadPart", "RemoveChunkStaging"} {
		if n := rig.fake.callCount(call); n != 0 {
			t.Fatalf("%s ran %d times against a foreign staging object", call, n)
		}
	}
}

func TestChunkedUploadDiskPreflight(t *testing.T) {
	const size = 3 * chunkMiB
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
		{"short counting the parts found", true, 2*size - chunkMiB - 1, true, true, true},
		{"exactly enough counting the parts found", true, 2*size - chunkMiB, true, true, false},
		{"unknown answer skips the check", false, 1, false, true, false},
		{"no df capability skips the check", false, 1, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newChunkRig(t)
			content := chunkContent(size, 7)
			rig.write("big.bin", content)
			key := rig.key("big.bin", chunkDest)
			if tc.resumed {
				rig.fake.seedStage(key, seedParts(content,
					transferlink.Range{Off: 0, Len: 512 << 10},
					transferlink.Range{Off: 512 << 10, Len: 512 << 10}))
			} else {
				rig.fake.streamFault = dropFirstStream(chunkMiB)
			}
			rig.fake.setDisk(tc.avail, tc.known)
			rig.fake.setCaps(transferremote.ChunkCaps{Own: true, Read: transferremote.ReadDD, Mtime: transferremote.MtimeGNU, DF: tc.df})

			res, err, _ := rig.upload(rig.freshEngine(), "big.bin", chunkDest, false)
			if tc.wantLimit {
				expectClass(t, err, transfercore.ClassLimit)
				if err.Error() != msgDiskShort {
					t.Fatalf("message = %q", err.Error())
				}
				if n := len(rig.fake.partAttempts()); n != 0 {
					t.Fatalf("%d parts were sent before the disk refusal", n)
				}
				assertNotPublished(t, rig.fake, chunkDest)
				assertCleanRemote(t, rig.fake)
				return
			}
			if err != nil {
				t.Fatalf("Upload: %v", err)
			}
			if res.Bytes != size {
				t.Fatalf("result = %+v", res)
			}
			assertPublished(t, rig.fake, chunkDest, content)
		})
	}
}

func TestChunkedUploadRechecksTheDiskAfterAPartFailure(t *testing.T) {
	for _, full := range []bool{true, false} {
		t.Run(fmt.Sprintf("disk full=%v", full), func(t *testing.T) {
			rig := newChunkRig(t)
			content := chunkContent(3*chunkMiB, 8)
			rig.write("big.bin", content)
			rig.fake.streamFault = dropFirstStream(chunkMiB)
			rig.fake.onPart = func(n int, rg transferlink.Range) {
				if n == 2 && full {
					rig.fake.setDisk(1, true)
				}
			}
			rig.fake.partFault = func(n int, rg transferlink.Range) *partFailure {
				if n == 2 {
					return &partFailure{cut: 1000, err: stageErr(24)}
				}
				return nil
			}

			_, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false)
			if full {
				expectClass(t, err, transfercore.ClassLimit)
			} else {
				expectClass(t, err, transfercore.ClassRemoteFailed)
			}
			if n := len(rig.fake.partAttempts()); n != 2 {
				t.Fatalf("%d part sessions ran, want 2 (a remote status is not retried)", n)
			}
			assertNotPublished(t, rig.fake, chunkDest)
			assertCleanRemote(t, rig.fake)
		})
	}
}

func TestChunkedUploadAssemblyHashMismatchIsIntegrity(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 9)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	planted := map[transferlink.Range][]byte{
		{Off: 0, Len: 512 << 10}:         chunkContent(512<<10, 99), // right length, wrong bytes
		{Off: 512 << 10, Len: 512 << 10}: content[512<<10 : chunkMiB],
	}
	rig.fake.seedStage(key, planted)

	res, err, _ := rig.upload(rig.freshEngine(), "big.bin", chunkDest, false)
	expectClass(t, err, transfercore.ClassIntegrity)
	assertNotPublished(t, rig.fake, chunkDest)
	assertCleanRemote(t, rig.fake)
	if n := rig.fake.callCount("PublishFile"); n != 0 {
		t.Fatalf("PublishFile ran %d times after a hash mismatch", n)
	}
	if res.Mode != ModeChunked {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestChunkedUploadCancelRemovesStaging(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 10)
	rig.write("big.bin", content)
	rig.fake.streamFault = dropFirstStream(chunkMiB)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rig.fake.onPart = func(n int, rg transferlink.Range) {
		if n == 2 {
			cancel()
		}
	}

	_, err := rig.engine.Upload(ctx, rig.root, "big.bin", chunkDest, false, nil)
	expectClass(t, err, transfercore.ClassCancelled)
	assertNotPublished(t, rig.fake, chunkDest)
	assertCleanRemote(t, rig.fake)
	if n := rig.fake.callCount("RemoveChunkStaging"); n != 1 {
		t.Fatalf("staging removal ran %d times after cancellation, want 1", n)
	}
}

func TestChunkedUploadGivesUpAfterEightAttemptsAndAnotherEngineResumes(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 11)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	rig.fake.streamFault = dropFirstStream(chunkMiB)
	// Two parts get through, then every part session drops.
	rig.fake.partFault = func(n int, rg transferlink.Range) *partFailure {
		if n >= 3 {
			return &partFailure{cut: 100 << 10}
		}
		return nil
	}

	res, err, log := rig.upload(rig.engine, "big.bin", chunkDest, false)
	expectClass(t, err, transfercore.ClassLinkUnstable)
	if err.Error() != transfercore.MsgLinkUnstable || err.Error() != "transfer link was too unstable to finish; a retry can resume" {
		t.Fatalf("message = %q", err.Error())
	}
	if n := len(rig.fake.partAttempts()); n != 2+transferlink.MaxNoProgress {
		t.Fatalf("%d part sessions ran, want 2 stored and %d dropped", n, transferlink.MaxNoProgress)
	}
	kept := rig.fake.stageParts(key)
	if len(kept) != 2 || sumLens(kept) != sumLens(rig.fake.storedParts()) {
		t.Fatalf("staging holds %v, want the two stored parts", kept)
	}
	if n := rig.fake.callCount("RemoveChunkStaging"); n != 0 {
		t.Fatalf("link_unstable removed its staging (%d removals)", n)
	}
	assertNotPublished(t, rig.fake, chunkDest)
	if res.Mode != ModeChunked || res.Bytes != sumLens(kept) || res.ChunksDone != 2 || res.Attempts != 1+2+transferlink.MaxNoProgress {
		t.Fatalf("failed result = %+v", res)
	}
	assertMonotone(t, log.items)

	// The link works again; a brand-new engine continues from the parts on
	// the remote side with no profile and no second stream.
	rig.fake.partFault = nil
	resumedFrom := sumLens(kept)
	res2, err2, _ := rig.upload(rig.freshEngine(), "big.bin", chunkDest, false)
	if err2 != nil {
		t.Fatalf("resume: %v", err2)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	assertCleanRemote(t, rig.fake)
	if n := rig.fake.callCount("WriteFile"); n != 1 {
		t.Fatalf("the resume streamed again (%d streams)", n)
	}
	attempts := rig.fake.partAttempts()
	if first := attempts[2+transferlink.MaxNoProgress]; first.Off != resumedFrom {
		t.Fatalf("resume started at %d, want %d", first.Off, resumedFrom)
	}
	if res2.Bytes != int64(len(content)) || res2.Mode != ModeChunked {
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
			rig := newChunkRig(t)
			content := chunkContent(tc.size, 12)
			rig.write("f.bin", content)
			rig.fake.streamFault = dropFirstStream(int64(tc.size) / 2)

			res, err, _ := rig.upload(rig.engine, "f.bin", chunkDest, false)
			if tc.chunked {
				if err != nil {
					t.Fatalf("Upload: %v", err)
				}
				assertPublished(t, rig.fake, chunkDest, content)
				if res.Mode != ModeChunked || res.ChunksDone != 2 {
					t.Fatalf("result = %+v", res)
				}
				return
			}
			expectClass(t, err, transfercore.ClassRemoteFailed)
			expectNoResult(t, res)
			assertNotPublished(t, rig.fake, chunkDest)
			assertCleanRemote(t, rig.fake)
			for _, call := range []string{"ListStaging", "EnsureStaging", "UploadPart", "RemoveChunkStaging"} {
				if n := rig.fake.callCount(call); n != 0 {
					t.Fatalf("%s ran %d times for a small file", call, n)
				}
			}
			if n := rig.fake.callCount("WriteFile"); n != 1 {
				t.Fatalf("WriteFile ran %d times, want 1 (no retry)", n)
			}
		})
	}
}

func TestChunkedUploadWithoutChunkCapabilitiesKeepsTheLegacyBehaviour(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 13)
	rig.write("big.bin", content)
	rig.fake.setCaps(transferremote.ChunkCaps{})
	rig.fake.streamFault = dropFirstStream(chunkMiB)

	res, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false)
	expectClass(t, err, transfercore.ClassRemoteFailed)
	expectNoResult(t, res)
	assertNotPublished(t, rig.fake, chunkDest)
	assertCleanRemote(t, rig.fake)
	for _, call := range []string{"CollectStaging", "ListStaging", "EnsureStaging", "UploadPart", "RemoveChunkStaging", "DiskAvailable"} {
		if n := rig.fake.callCount(call); n != 0 {
			t.Fatalf("%s ran %d times on a target without chunk capabilities", call, n)
		}
	}
	if n := rig.fake.callCount("WriteFile"); n != 1 {
		t.Fatalf("WriteFile ran %d times, want 1", n)
	}
}

func TestChunkedUploadNonLinkFailureIsNotRetried(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 14)
	rig.write("big.bin", content)
	rig.fake.streamFault = func(n int) *partFailure {
		return &partFailure{cut: chunkMiB, err: stageErr(24)}
	}

	res, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false)
	expectClass(t, err, transfercore.ClassRemoteFailed)
	expectNoResult(t, res)
	assertNotPublished(t, rig.fake, chunkDest)
	assertCleanRemote(t, rig.fake)
	if n := rig.fake.callCount("WriteFile"); n != 1 {
		t.Fatalf("WriteFile ran %d times, want 1", n)
	}
	for _, call := range []string{"EnsureStaging", "UploadPart"} {
		if n := rig.fake.callCount(call); n != 0 {
			t.Fatalf("%s ran %d times after a remote exit status", call, n)
		}
	}
}

func TestChunkedUploadProfileCarriesOverToTheNextJob(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 15)
	rig.write("one.bin", content)
	rig.write("two.bin", content)
	rig.fake.streamFault = dropFirstStream(chunkMiB)

	if _, err, _ := rig.upload(rig.engine, "one.bin", "/data/one.bin", false); err != nil {
		t.Fatalf("first job: %v", err)
	}
	streams := rig.fake.callCount("WriteFile")
	res, err, _ := rig.upload(rig.engine, "two.bin", "/data/two.bin", false)
	if err != nil {
		t.Fatalf("second job: %v", err)
	}
	if n := rig.fake.callCount("WriteFile"); n != streams {
		t.Fatalf("the second job streamed (%d streams, was %d): it ignored the profile", n, streams)
	}
	// No stream: one session per part, one assembly.
	if res.Mode != ModeChunked || res.Attempts != res.ChunksDone+1 {
		t.Fatalf("second job result = %+v", res)
	}
	assertPublished(t, rig.fake, "/data/two.bin", content)
}

func TestChunkedUploadPublicationSemanticsMatchTheStream(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("overwrite=%v", overwrite), func(t *testing.T) {
			rig := newChunkRig(t)
			content := chunkContent(3*chunkMiB, 16)
			rig.write("big.bin", content)
			rig.fake.put(chunkDest, []byte("old content"))
			rig.fake.streamFault = dropFirstStream(chunkMiB)

			_, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, overwrite)
			if overwrite {
				if err != nil {
					t.Fatalf("Upload: %v", err)
				}
				assertPublished(t, rig.fake, chunkDest, content)
			} else {
				expectClass(t, err, transfercore.ClassExists)
				got, _ := rig.fake.get(chunkDest)
				if !bytes.Equal(got, []byte("old content")) {
					t.Fatal("the existing destination was modified")
				}
			}
			assertCleanRemote(t, rig.fake)
		})
	}
}

func TestChunkedUploadCollectsStaleStagingAtPreflightAndIgnoresItsFailure(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 17)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	rig.fake.gcErr = transferremote.LinkFailure()

	if _, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if len(rig.fake.gcLog) != 1 || rig.fake.gcLog[0] != (gcCall{parent: "/data", exclude: key}) {
		t.Fatalf("garbage collection calls = %+v", rig.fake.gcLog)
	}
}

func TestChunkedUploadRemovesIgnoredEntriesFoundOnResume(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 18)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	seeded := seedParts(content, transferlink.Range{Off: 0, Len: 512 << 10})
	seeded[transferlink.Range{Off: 512 << 10, Len: 512 << 10}] = []byte("a lying size") // name says 512 KiB
	rig.fake.seedStage(key, seeded)

	if _, err, _ := rig.upload(rig.freshEngine(), "big.bin", chunkDest, false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	if len(rig.fake.removed) != 1 || len(rig.fake.removed[0]) != 1 || rig.fake.removed[0][0] != "part-524288-524288" {
		t.Fatalf("removed entries = %v", rig.fake.removed)
	}
	if first := rig.fake.partAttempts()[0]; first.Off != 512<<10 {
		t.Fatalf("first part = %v, want the lying entry's range to be sent again", first)
	}
}

func TestChunkedUploadCorruptStagingRestartsOnceOnly(t *testing.T) {
	t.Run("once", func(t *testing.T) {
		rig := newChunkRig(t)
		content := chunkContent(3*chunkMiB, 19)
		rig.write("big.bin", content)
		rig.fake.streamFault = dropFirstStream(chunkMiB)
		rig.fake.overflowLists[2] = true // 1 is the lookup, 2 the first resync

		if _, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false); err != nil {
			t.Fatalf("Upload: %v", err)
		}
		assertPublished(t, rig.fake, chunkDest, content)
		assertCleanRemote(t, rig.fake)
		if n := rig.fake.callCount("RemoveChunkStaging"); n != 2 {
			t.Fatalf("staging removals = %d, want the restart and the final one", n)
		}
	})
	t.Run("twice", func(t *testing.T) {
		rig := newChunkRig(t)
		content := chunkContent(3*chunkMiB, 20)
		rig.write("big.bin", content)
		rig.fake.streamFault = dropFirstStream(chunkMiB)
		rig.fake.overflowLists[2] = true
		rig.fake.overflowLists[3] = true

		_, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false)
		expectClass(t, err, transfercore.ClassRemoteFailed)
		assertNotPublished(t, rig.fake, chunkDest)
		assertCleanRemote(t, rig.fake)
	})
}

func TestChunkedUploadVanishedStagingRestartsFromZeroWithMonotoneBytes(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 21)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	rig.fake.streamFault = dropFirstStream(chunkMiB)
	rig.fake.onPart = func(n int, rg transferlink.Range) {
		if n == 3 {
			rig.fake.dropStage(key) // someone removed it after two parts
		}
	}

	_, err, log := rig.upload(rig.engine, "big.bin", chunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	assertCleanRemote(t, rig.fake)
	assertMonotone(t, log.items)
	if n := rig.fake.callCount("EnsureStaging"); n != 2 {
		t.Fatalf("EnsureStaging ran %d times, want the entry and one re-creation", n)
	}
}

func TestChunkedUploadAssemblyDropKeepsThePartsAndReassembles(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 22)
	rig.write("big.bin", content)
	rig.fake.streamFault = dropFirstStream(chunkMiB)
	rig.fake.assembleFault = func(n int) error {
		if n == 1 {
			return transferremote.LinkFailure()
		}
		return nil
	}

	res, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	assertCleanRemote(t, rig.fake)
	if n := rig.fake.callCount("AssembleStaging"); n != 2 {
		t.Fatalf("AssembleStaging ran %d times, want 2", n)
	}
	stored := rig.fake.storedParts()
	if n := len(rig.fake.partAttempts()); n != len(stored) {
		t.Fatalf("%d part sessions for %d parts: a part was sent again after the assembly drop", n, len(stored))
	}
	if res.Attempts != 1+len(stored)+2 {
		t.Fatalf("attempts = %d, want %d", res.Attempts, 1+len(stored)+2)
	}
}

func TestChunkedUploadPublicationDropReassemblesAndPublishesOnce(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 23)
	rig.write("big.bin", content)
	rig.fake.streamFault = dropFirstStream(chunkMiB)
	rig.fake.publishFault = func(n int) error {
		if n == 1 {
			return transferremote.LinkFailure()
		}
		return nil
	}

	if _, err, _ := rig.upload(rig.engine, "big.bin", chunkDest, false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	assertCleanRemote(t, rig.fake)
	if n := rig.fake.publishCount(); n != 1 {
		t.Fatalf("published %d times, want once", n)
	}
	if n := rig.fake.callCount("AssembleStaging"); n != 2 {
		t.Fatalf("AssembleStaging ran %d times, want 2", n)
	}
}

func TestChunkedUploadForeignAtEnsureBeforeAnyStreamFallsBack(t *testing.T) {
	rig := newChunkRig(t)
	content := chunkContent(3*chunkMiB, 24)
	rig.write("one.bin", content)
	rig.write("two.bin", content)
	rig.fake.streamFault = dropFirstStream(chunkMiB)
	if _, err, _ := rig.upload(rig.engine, "one.bin", "/data/one.bin", false); err != nil {
		t.Fatalf("first job: %v", err)
	}
	parts := len(rig.fake.partAttempts())
	// The profile now sends the next job straight to chunked mode, where the
	// staging name turns out to be foreign before any stream was tried.
	rig.fake.ensureForeign[rig.key("two.bin", "/data/two.bin")] = true

	res, err, _ := rig.upload(rig.engine, "two.bin", "/data/two.bin", false)
	if err != nil {
		t.Fatalf("second job: %v", err)
	}
	assertPublished(t, rig.fake, "/data/two.bin", content)
	if n := rig.fake.callCount("WriteFile"); n != 2 {
		t.Fatalf("WriteFile ran %d times, want the dropped stream and the fallback stream", n)
	}
	if n := len(rig.fake.partAttempts()); n != parts {
		t.Fatalf("the second job sent parts (%d, was %d)", n, parts)
	}
	if res.Mode != ModeStream || res.Attempts != 1 || res.ChunksDone != 0 {
		t.Fatalf("second job result = %+v", res)
	}
}
