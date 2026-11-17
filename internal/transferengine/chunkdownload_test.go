package transferengine

import (
	"bytes"
	"context"
	"crypto/sha256"
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

const dlRemote = "/data/remote.bin"

// dlRig is one engine over the in-memory chunk remote with a virtual clock and
// a real temporary transfer root: no test here sleeps or waits on a real
// timer, and the local staging, parts and publication are the real ones.
type dlRig struct {
	t      *testing.T
	clock  *vclock
	fake   *fakeDownloadRemote
	engine *Engine
	root   *transferlocal.Root
}

func newDLRig(t *testing.T) *dlRig {
	t.Helper()
	clock := newVClock()
	rig := &dlRig{t: t, clock: clock, fake: newFakeDownloadRemote(clock), root: testRoot(t)}
	rig.engine = rig.freshEngine()
	return rig
}

// freshEngine returns an engine of the same target with an empty link
// profile: a new keeper process.
func (r *dlRig) freshEngine() *Engine {
	r.t.Helper()
	profile := transferlink.NewProfile(transferlink.Config{Now: r.clock.Now})
	engine, err := NewWithOptions(r.fake, transfercore.DefaultLimits(), Options{Target: "t1", Profile: profile, Now: r.clock.Now})
	if err != nil {
		r.t.Fatalf("NewWithOptions: %v", err)
	}
	return engine
}

func (r *dlRig) put(content []byte) { r.fake.put(dlRemote, content) }

// key is the staging key the engine derives for the current remote file.
func (r *dlRig) key(local string) string {
	r.t.Helper()
	data, ok := r.fake.get(dlRemote)
	if !ok {
		r.t.Fatal("no remote file")
	}
	return transferremote.StagingKey("t1", dlRemote, local, strconv.Itoa(len(data)), strconv.FormatInt(r.fake.currentMTime(), 10))
}

func (r *dlRig) localPath(local string) string {
	return filepath.Join(r.root.Dir(), filepath.FromSlash(local))
}

// stageDir is where the keyed staging directory of local lives.
func (r *dlRig) stageDir(local string) string {
	return filepath.Join(filepath.Dir(r.localPath(local)), ".ssjack-transfer-"+r.key(local))
}

func (r *dlRig) download(engine *Engine, local string, overwrite bool) (Result, error, *progressLog) {
	log := &progressLog{}
	res, err := engine.Download(context.Background(), r.root, dlRemote, local, overwrite, log.add)
	return res, err, log
}

// seedWith creates the keyed staging directory of local, recording sum as the
// pre-hash, and stores the given parts in it, as an earlier process left them.
func (r *dlRig) seedWith(local string, sum [32]byte, parts map[transferlink.Range][]byte) {
	r.t.Helper()
	s, state, err := r.root.OpenChunkStaging(local, r.key(local), sum, false, true)
	if err != nil || state != transferlocal.ChunkCreated {
		r.t.Fatalf("seed: OpenChunkStaging = %v, %v", state, err)
	}
	for rg, data := range parts {
		w, err := s.CreatePart(rg)
		if err != nil {
			r.t.Fatalf("seed: CreatePart: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			r.t.Fatalf("seed: Write: %v", err)
		}
		if err := w.Commit(); err != nil {
			r.t.Fatalf("seed: Commit: %v", err)
		}
	}
}

// seed stores correct parts of content.
func (r *dlRig) seed(local string, content []byte, ranges ...transferlink.Range) {
	r.t.Helper()
	r.seedWith(local, sha256.Sum256(content), seedParts(content, ranges...))
}

// kept lists the parts the staging directory of local holds, after checking
// that nothing but the marker and finished parts is in it.
func (r *dlRig) kept(local string, content []byte) []transferlink.Range {
	r.t.Helper()
	dir := r.stageDir(local)
	entries, err := os.ReadDir(dir)
	if err != nil {
		r.t.Fatalf("staging directory: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name != "marker" && !strings.HasPrefix(name, "part-") || strings.HasSuffix(name, ".tmp") {
			r.t.Fatalf("staging holds the stray entry %q", name)
		}
	}
	s, state, err := r.root.OpenChunkStaging(local, r.key(local), sha256.Sum256(content), false, false)
	if err != nil || state != transferlocal.ChunkReused {
		r.t.Fatalf("kept: OpenChunkStaging = %v, %v", state, err)
	}
	parts, overflow, err := s.ListParts(int64(len(content)), 1<<20)
	if err != nil || overflow {
		r.t.Fatalf("kept: ListParts = %v %v", overflow, err)
	}
	return parts
}

func (r *dlRig) assertDownloaded(local string, want []byte) {
	r.t.Helper()
	got, err := os.ReadFile(r.localPath(local))
	if err != nil || !bytes.Equal(got, want) {
		r.t.Fatalf("%s is not downloaded byte-exact (err=%v)", local, err)
	}
	noStagingLeft(r.t, filepath.Dir(r.localPath(local)))
}

func (r *dlRig) assertAbsent(local string) {
	r.t.Helper()
	if _, err := os.Lstat(r.localPath(local)); !os.IsNotExist(err) {
		r.t.Fatalf("%s exists (err=%v)", local, err)
	}
}

func dlDropFirstStream(cut int64) func(int) *partFailure {
	return func(n int) *partFailure {
		if n == 1 {
			return &partFailure{cut: cut}
		}
		return nil
	}
}

// dlSnapshot renders a directory tree (names and file contents).
func dlSnapshot(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Name())
		full := filepath.Join(dir, e.Name())
		switch {
		case e.IsDir():
			b.WriteString(" [" + dlSnapshot(t, full) + "]")
		case e.Type().IsRegular():
			data, err := os.ReadFile(full)
			if err != nil {
				t.Fatal(err)
			}
			b.WriteString(" " + string(data))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func makeForeignStage(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChunkedDownloadStreamDropThenChunkedCompletion(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 31)
	rig.put(content)
	rig.fake.readFault = dlDropFirstStream(chunkMiB)

	res, err, log := rig.download(rig.engine, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	ranges := rig.fake.ranges()
	assertTiles(t, int64(len(content)), ranges)
	if res.Kind != KindFile || res.Files != 1 || res.Bytes != int64(len(content)) || res.SHA256 != sumHex(content) {
		t.Fatalf("result = %+v", res)
	}
	if res.Mode != ModeChunked || res.ChunksDone != len(ranges) || res.ChunksTotal != len(ranges) {
		t.Fatalf("chunk telemetry = %+v, want chunked with %d parts", res, len(ranges))
	}
	// One stream, one session per part, one assembly.
	if res.Attempts != 1+len(ranges)+1 {
		t.Fatalf("attempts = %d, want %d", res.Attempts, 1+len(ranges)+1)
	}
	if res.BytesPerSecond <= 0 || res.ChunkBytes <= 0 {
		t.Fatalf("telemetry has no speed or chunk size: %+v", res)
	}
	if n := rig.fake.readCount(); n != 1 {
		t.Fatalf("ReadFile ran %d times, want the one dropped stream", n)
	}
	// One look at the source before the key, one before each part, one after
	// the last part.
	if n := rig.fake.statCount(); n != len(ranges)+2 {
		t.Fatalf("StatSource ran %d times, want %d", n, len(ranges)+2)
	}
	for _, c := range rig.fake.rangeCalled() {
		if c.grid < c.part.Len {
			t.Fatalf("range %v was read with the smaller grid %d", c.part, c.grid)
		}
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

func TestChunkedDownloadResumesFromPartsOfAPreviousProcess(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 32)
	rig.put(content)
	seeded := []transferlink.Range{{Off: 0, Len: 512 << 10}, {Off: 512 << 10, Len: 512 << 10}}
	rig.seed("big.bin", content, seeded...)

	// A new engine: empty link profile, as after a keeper restart.
	res, err, log := rig.download(rig.freshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	if n := rig.fake.readCount(); n != 0 {
		t.Fatalf("a resumed transfer streamed the whole file (%d streams)", n)
	}
	attempts := rig.fake.ranges()
	if len(attempts) == 0 || attempts[0].Off != chunkMiB {
		t.Fatalf("first range read = %v, want it to start after the parts found on resume", attempts)
	}
	assertTiles(t, int64(len(content)), append(append([]transferlink.Range(nil), attempts...), seeded...))
	if res.Mode != ModeChunked || res.Bytes != int64(len(content)) || res.ChunksDone != len(attempts)+2 {
		t.Fatalf("result = %+v", res)
	}
	if res.Attempts != len(attempts)+1 {
		t.Fatalf("attempts = %d, want %d part sessions and one assembly", res.Attempts, len(attempts))
	}
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

func TestChunkedDownloadHalvesAfterADropAndMixesPartSizes(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 33)
	rig.put(content)
	seed := transferlink.Range{Off: 0, Len: 600 << 10}
	rig.seed("big.bin", content, seed)
	rig.fake.rangeFault = func(n int, rg transferlink.Range) *partFailure {
		if n == 1 {
			return &partFailure{cut: 100 << 10}
		}
		return nil
	}

	res, err, log := rig.download(rig.freshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	calls := rig.fake.rangeCalled()
	// The size found on resume seeds the chunk size; the drop halves it, and
	// the next attempt resumes at the same gap with a smaller part.
	if len(calls) < 2 || calls[0].part != (transferlink.Range{Off: 600 << 10, Len: 600 << 10}) ||
		calls[1].part.Off != calls[0].part.Off || calls[1].part.Len >= calls[0].part.Len {
		t.Fatalf("range reads = %v", calls)
	}
	// The dropped part is not in the coverage: the parts are the seed and every
	// successful read.
	var stored []transferlink.Range
	for _, c := range calls[1:] {
		stored = append(stored, c.part)
	}
	all := append([]transferlink.Range{seed}, stored...)
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

func TestChunkedDownloadSourceChangedMidway(t *testing.T) {
	mutations := map[string]func(rig *dlRig, content []byte){
		"size": func(rig *dlRig, content []byte) {
			rig.put(append(append([]byte(nil), content...), 'x'))
		},
		"modification time": func(rig *dlRig, content []byte) {
			rig.fake.setMTime(dlMTime + 10)
		},
	}
	for name, mutate := range mutations {
		t.Run(strings.ReplaceAll(name, " ", "-"), func(t *testing.T) {
			rig := newDLRig(t)
			content := chunkContent(3*chunkMiB, 34)
			rig.put(content)
			rig.fake.readFault = dlDropFirstStream(chunkMiB)
			// Look number 3 is the one before the second part.
			rig.fake.onStat = func(n int) {
				if n == 3 {
					mutate(rig, content)
				}
			}

			res, err, _ := rig.download(rig.engine, "big.bin", false)
			expectClass(t, err, transfercore.ClassIntegrity)
			rig.assertAbsent("big.bin")
			noStagingLeft(t, rig.root.Dir())
			ranges := rig.fake.ranges()
			if len(ranges) != 1 {
				t.Fatalf("%d range reads ran, want 1 (the change is caught before part 2)", len(ranges))
			}
			if res.Mode != ModeChunked || res.Bytes != ranges[0].Len {
				t.Fatalf("failed result = %+v", res)
			}
		})
	}
}

func TestChunkedDownloadSourceContentChangedBehindTheSameSizeAndTime(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 35)
	rig.put(content)
	rig.fake.readFault = dlDropFirstStream(chunkMiB)
	rig.fake.onStat = func(n int) {
		if n == 3 {
			changed := append([]byte(nil), content...)
			changed[len(changed)-1] ^= 0xff
			changed[2*chunkMiB] ^= 0xff
			rig.put(changed)
		}
	}

	res, err, _ := rig.download(rig.engine, "big.bin", false)
	expectClass(t, err, transfercore.ClassIntegrity)
	rig.assertAbsent("big.bin")
	noStagingLeft(t, rig.root.Dir())
	// Only the whole-file hash can see this: every part was read first.
	if res.Mode != ModeChunked || res.Bytes != int64(len(content)) {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestChunkedDownloadRemoteThatShrinksFailsIntegrity(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 36)
	rig.put(content)
	rig.fake.readFault = dlDropFirstStream(chunkMiB)
	rig.fake.onRange = func(n int, rg transferlink.Range) {
		if n == 2 {
			rig.put(content[:rg.Off+100]) // most of the second range is no longer there
		}
	}

	_, err, _ := rig.download(rig.engine, "big.bin", false)
	expectClass(t, err, transfercore.ClassIntegrity)
	rig.assertAbsent("big.bin")
	noStagingLeft(t, rig.root.Dir())
}

func TestChunkedDownloadForeignStagingFallsBackToAStream(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 37)
	rig.put(content)
	foreign := rig.stageDir("big.bin")
	makeForeignStage(t, foreign)
	before := dlSnapshot(t, foreign)

	res, err, _ := rig.download(rig.engine, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	want := Result{Kind: KindFile, Files: 1, Bytes: int64(len(content)), SHA256: sumHex(content)}
	if res != want {
		t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
	}
	got, readErr := os.ReadFile(rig.localPath("big.bin"))
	if readErr != nil || !bytes.Equal(got, content) {
		t.Fatal("the file is not downloaded byte-exact")
	}
	if n := len(rig.fake.ranges()); n != 0 {
		t.Fatalf("%d range reads ran next to a foreign staging object", n)
	}
	if after := dlSnapshot(t, foreign); after != before {
		t.Fatal("the foreign object was touched")
	}
}

func TestChunkedDownloadForeignStagingAfterADropFailsRefused(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 38)
	rig.put(content)
	foreign := rig.stageDir("big.bin")
	rig.fake.readFault = func(n int) *partFailure {
		if n == 1 {
			makeForeignStage(t, foreign) // appears after the lookup, before the chunked entry
			return &partFailure{cut: chunkMiB}
		}
		return nil
	}

	_, err, _ := rig.download(rig.engine, "big.bin", false)
	expectClass(t, err, transfercore.ClassRefusedPath)
	rig.assertAbsent("big.bin")
	if n := len(rig.fake.ranges()); n != 0 {
		t.Fatalf("%d range reads ran against a foreign staging object", n)
	}
	if got := dlSnapshot(t, foreign); got != "keep keep\n" {
		t.Fatalf("the foreign object was touched: %q", got)
	}
	entries, readErr := os.ReadDir(rig.root.Dir())
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("root holds %v (%v), want only the foreign object", entries, readErr)
	}
}

func TestChunkedDownloadAssemblyHashMismatchIsIntegrity(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 39)
	rig.put(content)
	planted := map[transferlink.Range][]byte{
		{Off: 0, Len: chunkMiB}:            chunkContent(chunkMiB, 99), // right length, wrong bytes
		{Off: chunkMiB, Len: chunkMiB}:     content[chunkMiB : 2*chunkMiB],
		{Off: 2 * chunkMiB, Len: chunkMiB}: content[2*chunkMiB:],
	}
	rig.seedWith("big.bin", sha256.Sum256(content), planted)

	res, err, _ := rig.download(rig.freshEngine(), "big.bin", false)
	expectClass(t, err, transfercore.ClassIntegrity)
	rig.assertAbsent("big.bin")
	noStagingLeft(t, rig.root.Dir())
	if n := len(rig.fake.ranges()); n != 0 {
		t.Fatalf("%d range reads ran for a complete staging", n)
	}
	if res.Mode != ModeChunked || res.Bytes != int64(len(content)) {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestChunkedDownloadCancelRemovesStaging(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 40)
	rig.put(content)
	rig.fake.readFault = dlDropFirstStream(chunkMiB)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rig.fake.onRange = func(n int, rg transferlink.Range) {
		if n == 2 {
			cancel()
		}
	}

	res, err := rig.engine.Download(ctx, rig.root, dlRemote, "big.bin", false, nil)
	expectClass(t, err, transfercore.ClassCancelled)
	rig.assertAbsent("big.bin")
	noStagingLeft(t, rig.root.Dir())
	ranges := rig.fake.ranges()
	if res.Mode != ModeChunked || len(ranges) != 2 || res.Bytes != ranges[0].Len {
		t.Fatalf("failed result = %+v after %v", res, ranges)
	}
}

func TestChunkedDownloadGivesUpAfterEightAttemptsAndAnotherEngineResumes(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 41)
	rig.put(content)
	rig.fake.readFault = dlDropFirstStream(chunkMiB)
	// Two parts get through, then every range read drops.
	rig.fake.rangeFault = func(n int, rg transferlink.Range) *partFailure {
		if n >= 3 {
			return &partFailure{cut: 100 << 10}
		}
		return nil
	}

	res, err, log := rig.download(rig.engine, "big.bin", false)
	expectClass(t, err, transfercore.ClassLinkUnstable)
	if err.Error() != transfercore.MsgLinkUnstable || err.Error() != "transfer link was too unstable to finish; a retry can resume" {
		t.Fatalf("message = %q", err.Error())
	}
	if n := len(rig.fake.ranges()); n != 2+transferlink.MaxNoProgress {
		t.Fatalf("%d range reads ran, want 2 stored and %d dropped", n, transferlink.MaxNoProgress)
	}
	rig.assertAbsent("big.bin")
	kept := rig.kept("big.bin", content)
	if len(kept) != 2 {
		t.Fatalf("staging holds %v, want the two stored parts", kept)
	}
	if res.Mode != ModeChunked || res.Bytes != sumLens(kept) || res.ChunksDone != 2 || res.Attempts != 1+2+transferlink.MaxNoProgress {
		t.Fatalf("failed result = %+v", res)
	}
	assertMonotone(t, log.items)

	// The link works again; a brand-new engine continues from the parts on
	// disk with no profile and no second stream.
	rig.fake.rangeFault = nil
	resumedFrom := sumLens(kept)
	res2, err2, _ := rig.download(rig.freshEngine(), "big.bin", false)
	if err2 != nil {
		t.Fatalf("resume: %v", err2)
	}
	rig.assertDownloaded("big.bin", content)
	if n := rig.fake.readCount(); n != 1 {
		t.Fatalf("the resume streamed again (%d streams)", n)
	}
	if first := rig.fake.ranges()[2+transferlink.MaxNoProgress]; first.Off != resumedFrom {
		t.Fatalf("resume started at %d, want %d", first.Off, resumedFrom)
	}
	if res2.Bytes != int64(len(content)) || res2.Mode != ModeChunked {
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
			rig := newDLRig(t)
			content := chunkContent(tc.size, 42)
			rig.put(content)
			rig.fake.readFault = dlDropFirstStream(int64(tc.size) / 2)

			res, err, _ := rig.download(rig.engine, "f.bin", false)
			if tc.chunked {
				if err != nil {
					t.Fatalf("Download: %v", err)
				}
				rig.assertDownloaded("f.bin", content)
				if res.Mode != ModeChunked || res.ChunksDone != 2 {
					t.Fatalf("result = %+v", res)
				}
				return
			}
			expectClass(t, err, transfercore.ClassRemoteFailed)
			expectNoResult(t, res)
			rig.assertAbsent("f.bin")
			noStagingLeft(t, rig.root.Dir())
			for _, call := range []string{"StatSource", "ReadRange"} {
				if n := rig.fake.callCount(call); n != 0 {
					t.Fatalf("%s ran %d times for a small file", call, n)
				}
			}
			if n := rig.fake.readCount(); n != 1 {
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
			rig := newDLRig(t)
			content := chunkContent(3*chunkMiB, 43)
			rig.put(content)
			rig.fake.setCaps(c)
			rig.fake.readFault = dlDropFirstStream(chunkMiB)
			// Legacy behaviour touches no local staging of this kind at all: an
			// idle one stays where it is.
			stale := rig.staleStage("big.bin", chunkContent(10, 1), 72*time.Hour, 9)

			res, err, _ := rig.download(rig.engine, "big.bin", false)
			expectClass(t, err, transfercore.ClassRemoteFailed)
			expectNoResult(t, res)
			rig.assertAbsent("big.bin")
			for _, call := range []string{"StatSource", "ReadRange"} {
				if n := rig.fake.callCount(call); n != 0 {
					t.Fatalf("%s ran %d times on a target without download capabilities", call, n)
				}
			}
			if n := rig.fake.readCount(); n != 1 {
				t.Fatalf("ReadFile ran %d times, want 1", n)
			}
			if _, statErr := os.Lstat(stale); statErr != nil {
				t.Fatalf("the idle staging was collected without chunk capabilities: %v", statErr)
			}
		})
	}
}

// staleStage creates a keyed staging directory in the directory of local, with
// the pre-hash of content and a marker last touched age ago.
func (r *dlRig) staleStage(local string, content []byte, age time.Duration, n int) string {
	r.t.Helper()
	key := fmt.Sprintf("%032x", n)
	s, state, err := r.root.OpenChunkStaging(local, key, sha256.Sum256(content), false, true)
	if err != nil || state != transferlocal.ChunkCreated {
		r.t.Fatalf("staleStage: %v, %v", state, err)
	}
	dir := filepath.Join(filepath.Dir(r.localPath(local)), ".ssjack-transfer-"+key)
	old := time.Now().Add(-age)
	if err := os.Chtimes(filepath.Join(dir, "marker"), old, old); err != nil {
		r.t.Fatal(err)
	}
	_ = s
	return dir
}

func TestChunkedDownloadNonLinkFailureIsNotRetried(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 44)
	rig.put(content)
	rig.fake.readFault = func(n int) *partFailure {
		return &partFailure{cut: chunkMiB, err: stageErr(24)}
	}

	res, err, _ := rig.download(rig.engine, "big.bin", false)
	expectClass(t, err, transfercore.ClassRemoteFailed)
	expectNoResult(t, res)
	rig.assertAbsent("big.bin")
	noStagingLeft(t, rig.root.Dir())
	if n := rig.fake.readCount(); n != 1 {
		t.Fatalf("ReadFile ran %d times, want 1", n)
	}
	if n := len(rig.fake.ranges()); n != 0 {
		t.Fatalf("%d range reads ran after a remote exit status", n)
	}
}

func TestChunkedDownloadRangeReadRemoteStatusEndsTheJobAndRemovesStaging(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 45)
	rig.put(content)
	rig.fake.readFault = dlDropFirstStream(chunkMiB)
	rig.fake.rangeFault = func(n int, rg transferlink.Range) *partFailure {
		if n == 2 {
			return &partFailure{cut: 1000, err: stageErr(24)}
		}
		return nil
	}

	_, err, _ := rig.download(rig.engine, "big.bin", false)
	expectClass(t, err, transfercore.ClassRemoteFailed)
	if n := len(rig.fake.ranges()); n != 2 {
		t.Fatalf("%d range reads ran, want 2 (a remote status is not retried)", n)
	}
	rig.assertAbsent("big.bin")
	noStagingLeft(t, rig.root.Dir())
}

func TestChunkedDownloadProfileCarriesOverToTheNextJob(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 46)
	rig.put(content)
	rig.fake.readFault = dlDropFirstStream(chunkMiB)

	if _, err, _ := rig.download(rig.engine, "one.bin", false); err != nil {
		t.Fatalf("first job: %v", err)
	}
	streams := rig.fake.readCount()
	res, err, _ := rig.download(rig.engine, "two.bin", false)
	if err != nil {
		t.Fatalf("second job: %v", err)
	}
	if n := rig.fake.readCount(); n != streams {
		t.Fatalf("the second job streamed (%d streams, was %d): it ignored the profile", n, streams)
	}
	// No stream: one session per part, one assembly.
	if res.Mode != ModeChunked || res.Attempts != res.ChunksDone+1 {
		t.Fatalf("second job result = %+v", res)
	}
	rig.assertDownloaded("two.bin", content)
}

func TestChunkedDownloadPublicationSemanticsMatchTheStream(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("overwrite %v", overwrite), func(t *testing.T) {
			rig := newDLRig(t)
			content := chunkContent(3*chunkMiB, 47)
			rig.put(content)
			writeLocalFile(t, rig.root, "big.bin", []byte("old content"))
			// Complete parts from an earlier process: no stream is tried, so the
			// existing destination is met by the chunked path itself.
			rig.seed("big.bin", content,
				transferlink.Range{Off: 0, Len: chunkMiB},
				transferlink.Range{Off: chunkMiB, Len: chunkMiB},
				transferlink.Range{Off: 2 * chunkMiB, Len: chunkMiB})

			_, err, _ := rig.download(rig.freshEngine(), "big.bin", overwrite)
			if overwrite {
				if err != nil {
					t.Fatalf("Download: %v", err)
				}
				rig.assertDownloaded("big.bin", content)
				return
			}
			expectClass(t, err, transfercore.ClassExists)
			got, readErr := os.ReadFile(rig.localPath("big.bin"))
			if readErr != nil || !bytes.Equal(got, []byte("old content")) {
				t.Fatal("the existing destination was modified")
			}
			noStagingLeft(t, rig.root.Dir())
			if n := len(rig.fake.ranges()); n != 0 {
				t.Fatalf("%d range reads ran for an existing destination", n)
			}
		})
	}
}

func TestChunkedDownloadDestinationAppearingBeforePublicationIsExists(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 48)
	rig.put(content)
	rig.seed("big.bin", content,
		transferlink.Range{Off: 0, Len: chunkMiB},
		transferlink.Range{Off: chunkMiB, Len: chunkMiB},
		transferlink.Range{Off: 2 * chunkMiB, Len: chunkMiB})
	// Look 1 is the preflight, look 2 the one before the assembly.
	rig.fake.onStat = func(n int) {
		if n == 2 {
			writeLocalFile(t, rig.root, "big.bin", []byte("late arrival"))
		}
	}

	_, err, _ := rig.download(rig.freshEngine(), "big.bin", false)
	expectClass(t, err, transfercore.ClassExists)
	got, readErr := os.ReadFile(rig.localPath("big.bin"))
	if readErr != nil || !bytes.Equal(got, []byte("late arrival")) {
		t.Fatal("the late destination was modified")
	}
	noStagingLeft(t, rig.root.Dir())
}

func TestChunkedDownloadForbiddenControlDirectoryIsRefused(t *testing.T) {
	for _, size := range []int{4 << 10, 3 * chunkMiB} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			rig := newDLRig(t)
			content := chunkContent(size, 49)
			rig.put(content)

			res, err, _ := rig.download(rig.engine, ".git/big.bin", false)
			expectClass(t, err, transfercore.ClassRefusedPath)
			expectNoResult(t, res)
			if n := rig.fake.callCount("ReadRange") + rig.fake.callCount("ReadFile"); n != 0 {
				t.Fatalf("%d reads ran for a forbidden destination", n)
			}
			entries, readErr := os.ReadDir(rig.root.Dir())
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("a refused destination left %v behind (%v)", entries, readErr)
			}
		})
	}
}

func TestChunkedDownloadCollectsStaleStagingAtPreflight(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(64<<10, 50) // small: the collection runs anyway
	rig.put(content)
	stale1 := rig.staleStage("big.bin", content, 72*time.Hour, 1)
	stale2 := rig.staleStage("big.bin", content, 25*time.Hour, 2)
	young := rig.staleStage("big.bin", content, 22*time.Hour, 3)
	foreign := filepath.Join(rig.root.Dir(), ".ssjack-transfer-"+fmt.Sprintf("%032x", 4))
	makeForeignStage(t, foreign)
	oneShot := filepath.Join(rig.root.Dir(), ".ssjack-transfer-0123456789ab")
	makeForeignStage(t, oneShot)
	plain := writeLocalFile(t, rig.root, "plain.txt", []byte("plain"))
	beforeForeign, beforeOneShot := dlSnapshot(t, foreign), dlSnapshot(t, oneShot)

	if _, err, _ := rig.download(rig.engine, "big.bin", false); err != nil {
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
	if dlSnapshot(t, foreign) != beforeForeign || dlSnapshot(t, oneShot) != beforeOneShot {
		t.Fatal("a foreign object was modified")
	}
}

func TestChunkedDownloadNeverCollectsItsOwnIdleStaging(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 51)
	rig.put(content)
	rig.seed("big.bin", content, transferlink.Range{Off: 0, Len: 512 << 10})
	dir := rig.stageDir("big.bin")
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "marker"), old, old); err != nil {
		t.Fatal(err)
	}

	res, err, _ := rig.download(rig.freshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	if n := rig.fake.readCount(); n != 0 {
		t.Fatalf("the idle own staging was collected and the file streamed (%d streams)", n)
	}
	if ranges := rig.fake.ranges(); len(ranges) == 0 || ranges[0].Off != 512<<10 {
		t.Fatalf("range reads = %v, want a resume after the part found", ranges)
	}
	if res.Mode != ModeChunked {
		t.Fatalf("result = %+v", res)
	}
}

func TestChunkedDownloadStagingOfAnotherPreHashIsDiscarded(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 52)
	rig.put(content)
	// Same key (size and time), but the parts belong to other bytes: the marker
	// records another pre-hash.
	other := chunkContent(len(content), 53)
	rig.seedWith("big.bin", sha256.Sum256(other), seedParts(other,
		transferlink.Range{Off: 0, Len: chunkMiB},
		transferlink.Range{Off: chunkMiB, Len: chunkMiB},
		transferlink.Range{Off: 2 * chunkMiB, Len: chunkMiB}))

	res, err, _ := rig.download(rig.freshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	want := Result{Kind: KindFile, Files: 1, Bytes: int64(len(content)), SHA256: sumHex(content)}
	if res != want {
		t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
	}
	if n := len(rig.fake.ranges()); n != 0 {
		t.Fatalf("%d range reads ran: the parts of another version were reused", n)
	}
}

func TestChunkedDownloadDiskPreflight(t *testing.T) {
	const size = 3 * chunkMiB
	cases := []struct {
		name      string
		avail     int64
		known     bool
		wantLimit bool
	}{
		{"short counting the parts found", 2*size - chunkMiB - 1, true, true},
		{"exactly enough counting the parts found", 2*size - chunkMiB, true, false},
		{"unknown answer skips the check", 1, false, false},
	}
	for _, tc := range cases {
		t.Run(strings.ReplaceAll(tc.name, " ", "-"), func(t *testing.T) {
			saved := diskFree
			t.Cleanup(func() { diskFree = saved })
			diskFree = func(*transferlocal.ChunkStaging) (int64, bool) { return tc.avail, tc.known }

			rig := newDLRig(t)
			content := chunkContent(size, 54)
			rig.put(content)
			rig.seed("big.bin", content, transferlink.Range{Off: 0, Len: chunkMiB})

			res, err, _ := rig.download(rig.freshEngine(), "big.bin", false)
			if tc.wantLimit {
				expectClass(t, err, transfercore.ClassLimit)
				if err.Error() != msgLocalDiskShort {
					t.Fatalf("message = %q", err.Error())
				}
				if n := len(rig.fake.ranges()); n != 0 {
					t.Fatalf("%d ranges were read before the disk refusal", n)
				}
				rig.assertAbsent("big.bin")
				noStagingLeft(t, rig.root.Dir())
				return
			}
			if err != nil {
				t.Fatalf("Download: %v", err)
			}
			if res.Bytes != size {
				t.Fatalf("result = %+v", res)
			}
			rig.assertDownloaded("big.bin", content)
		})
	}
}

func TestChunkedDownloadAssemblyDropKeepsThePartsAndTriesAgain(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 55)
	rig.put(content)
	rig.seed("big.bin", content,
		transferlink.Range{Off: 0, Len: chunkMiB},
		transferlink.Range{Off: chunkMiB, Len: chunkMiB},
		transferlink.Range{Off: 2 * chunkMiB, Len: chunkMiB})
	// Look 1 is the preflight, look 2 the first one before the assembly.
	rig.fake.statFault = func(n int) error {
		if n == 2 {
			return transferremote.LinkFailure()
		}
		return nil
	}

	res, err, _ := rig.download(rig.freshEngine(), "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	if n := rig.fake.statCount(); n != 3 {
		t.Fatalf("StatSource ran %d times, want the preflight, the dropped look and its retry", n)
	}
	if n := len(rig.fake.ranges()); n != 0 {
		t.Fatalf("%d parts were read again after the assembly drop", n)
	}
	if res.Mode != ModeChunked || res.Attempts != 2 {
		t.Fatalf("result = %+v, want two assembly attempts", res)
	}
}

func TestChunkedDownloadAssemblyKeepsDroppingThenAnotherEnginePublishes(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 56)
	rig.put(content)
	rig.seed("big.bin", content,
		transferlink.Range{Off: 0, Len: chunkMiB},
		transferlink.Range{Off: chunkMiB, Len: chunkMiB},
		transferlink.Range{Off: 2 * chunkMiB, Len: chunkMiB})
	rig.fake.statFault = func(n int) error {
		if n >= 2 {
			return transferremote.LinkFailure()
		}
		return nil
	}

	res, err, _ := rig.download(rig.freshEngine(), "big.bin", false)
	expectClass(t, err, transfercore.ClassLinkUnstable)
	if n := rig.fake.statCount(); n != 1+transferlink.MaxNoProgress {
		t.Fatalf("StatSource ran %d times, want the preflight and %d dropped looks", n, transferlink.MaxNoProgress)
	}
	if res.Mode != ModeChunked || res.Bytes != int64(len(content)) || res.Attempts != transferlink.MaxNoProgress {
		t.Fatalf("stranded result = %+v, want every byte verified in parts", res)
	}
	rig.assertAbsent("big.bin")
	if kept := rig.kept("big.bin", content); sumLens(kept) != int64(len(content)) || len(kept) != 3 {
		t.Fatalf("the parts did not stay intact: %v", kept)
	}

	rig.fake.statFault = nil
	res2, err2, _ := rig.download(rig.freshEngine(), "big.bin", false)
	if err2 != nil {
		t.Fatalf("second call after the assembly drops: %v", err2)
	}
	rig.assertDownloaded("big.bin", content)
	if n := len(rig.fake.ranges()); n != 0 || rig.fake.readCount() != 0 {
		t.Fatalf("second call read %d ranges and %d streams; want only the assembly", n, rig.fake.readCount())
	}
	if res2.Bytes != int64(len(content)) || res2.Mode != ModeChunked {
		t.Fatalf("second result = %+v", res2)
	}
}

func TestChunkedDownloadVanishedStagingRestartsFromZeroWithMonotoneBytes(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 57)
	rig.put(content)
	dir := rig.stageDir("big.bin")
	rig.fake.readFault = dlDropFirstStream(chunkMiB)
	// Look 1 is the preflight, looks 2 and 3 precede parts 1 and 2, look 4
	// precedes part 3: someone removes the staging just before it.
	rig.fake.onStat = func(n int) {
		if n == 4 {
			if err := os.RemoveAll(dir); err != nil {
				t.Errorf("remove staging: %v", err)
			}
		}
	}

	res, err, log := rig.download(rig.engine, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	assertMonotone(t, log.items)
	if res.Bytes != int64(len(content)) || res.Mode != ModeChunked {
		t.Fatalf("result = %+v", res)
	}
	if n := len(rig.fake.ranges()); n < 4 {
		t.Fatalf("%d range reads ran, want the lost parts to be read again", n)
	}
}

func TestChunkedDownloadRemovesIgnoredEntriesFoundOnResume(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 58)
	rig.put(content)
	rig.seed("big.bin", content, transferlink.Range{Off: 0, Len: 512 << 10})
	dir := rig.stageDir("big.bin")
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

	if _, err, _ := rig.download(rig.freshEngine(), "big.bin", false); err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	if first := rig.fake.ranges()[0]; first.Off != 512<<10 {
		t.Fatalf("first range = %v, want the lying entry's range to be read again", first)
	}
}

func TestChunkedDownloadPreflightLookFailuresDisableChunkingForTheCall(t *testing.T) {
	cases := map[string]struct {
		fault func(n int) error
		looks int
	}{
		"link failures": {func(n int) error { return transferremote.LinkFailure() }, statSourceTries},
		"remote status": {func(n int) error { return stageErr(24) }, 1},
	}
	for name, tc := range cases {
		t.Run(strings.ReplaceAll(name, " ", "-"), func(t *testing.T) {
			rig := newDLRig(t)
			content := chunkContent(3*chunkMiB, 59)
			rig.put(content)
			rig.fake.statFault = tc.fault

			res, err, _ := rig.download(rig.engine, "big.bin", false)
			if err != nil {
				t.Fatalf("Download: %v", err)
			}
			rig.assertDownloaded("big.bin", content)
			want := Result{Kind: KindFile, Files: 1, Bytes: int64(len(content)), SHA256: sumHex(content)}
			if res != want {
				t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
			}
			if n := rig.fake.statCount(); n != tc.looks {
				t.Fatalf("StatSource ran %d times, want %d", n, tc.looks)
			}
		})
	}
}

func TestChunkedDownloadPreflightRetriesADroppedLook(t *testing.T) {
	rig := newDLRig(t)
	content := chunkContent(3*chunkMiB, 60)
	rig.put(content)
	rig.fake.statFault = func(n int) error {
		if n == 1 {
			return transferremote.LinkFailure()
		}
		return nil
	}
	rig.fake.readFault = dlDropFirstStream(chunkMiB)

	res, err, _ := rig.download(rig.engine, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	if res.Mode != ModeChunked {
		t.Fatalf("result = %+v: the retried look did not enable chunking", res)
	}
}

func TestChunkedDownloadDirectoriesAreNeverChunked(t *testing.T) {
	rig := newDLRig(t)
	rig.fake.mkdir("/data/tree")
	rig.fake.put("/data/tree/big.bin", chunkContent(3*chunkMiB, 61))
	rig.fake.failTarOut = transferremote.LinkFailure()

	res, err := expectFinish(t, 30*time.Second, func() (Result, error) {
		return rig.engine.Download(context.Background(), rig.root, "/data/tree", "out", false, nil)
	})
	if err == nil {
		t.Fatal("a dropped directory transfer succeeded")
	}
	expectNoResult(t, res)
	rig.assertAbsent("out")
	noStagingLeft(t, rig.root.Dir())
	for _, call := range []string{"StatSource", "ReadRange", "ReadFile"} {
		if n := rig.fake.callCount(call); n != 0 {
			t.Fatalf("%s ran %d times for a directory", call, n)
		}
	}
	if n := rig.fake.callCount("TarOut"); n != 1 {
		t.Fatalf("TarOut ran %d times, want 1 (a dropped directory transfer has no second attempt)", n)
	}
}
