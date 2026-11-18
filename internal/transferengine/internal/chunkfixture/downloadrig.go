package chunkfixture

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
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// DlRig is one engine over the in-memory chunk remote with a virtual clock and
// a real temporary transfer root: no test here sleeps or waits on a real
// timer, and the local staging, parts and publication are the real ones.
type DlRig struct {
	T      *testing.T
	Clock  *testfixture.VClock
	Fake   *testfixture.FakeDownloadRemote
	Engine *transferengine.Engine
	Root   *transferlocal.Root
}

func NewDLRig(t *testing.T) *DlRig {
	t.Helper()
	clock := testfixture.NewVClock()
	rig := &DlRig{T: t, Clock: clock, Fake: testfixture.NewFakeDownloadRemote(clock), Root: enginetest.TestRoot(t)}
	rig.Engine = rig.FreshEngine()
	return rig
}

// FreshEngine returns an engine of the same target with an empty link
// profile: a new keeper process.
func (r *DlRig) FreshEngine() *transferengine.Engine {
	r.T.Helper()
	profile := transferlink.NewProfile(transferlink.Config{Now: r.Clock.Now})
	engine, err := transferengine.NewWithOptions(r.Fake, transfercore.DefaultLimits(), transferengine.Options{Target: "t1", Profile: profile, Now: r.Clock.Now})
	if err != nil {
		r.T.Fatalf("NewWithOptions: %v", err)
	}
	return engine
}

func (r *DlRig) Put(content []byte) { r.Fake.Put(DlRemote, content) }

// Key is the staging key the engine derives for the current remote file.
func (r *DlRig) Key(local string) string {
	r.T.Helper()
	data, ok := r.Fake.Get(DlRemote)
	if !ok {
		r.T.Fatal("no remote file")
	}
	return transferremote.StagingKey("t1", DlRemote, local, strconv.Itoa(len(data)), strconv.FormatInt(r.Fake.CurrentMTime(), 10))
}

func (r *DlRig) LocalPath(local string) string {
	return filepath.Join(r.Root.Dir(), filepath.FromSlash(local))
}

// StageDir is where the keyed staging directory of local lives.
func (r *DlRig) StageDir(local string) string {
	return filepath.Join(filepath.Dir(r.LocalPath(local)), ".ssjack-transfer-"+r.Key(local))
}

func (r *DlRig) Download(engine *transferengine.Engine, local string, overwrite bool) (transferengine.Result, error, *ProgressLog) {
	log := &ProgressLog{}
	res, err := engine.Download(context.Background(), r.Root, DlRemote, local, overwrite, log.Add)
	return res, err, log
}

// SeedWith creates the keyed staging directory of local, recording sum as the
// pre-hash, and stores the given parts in it, as an earlier process left them.
func (r *DlRig) SeedWith(local string, sum [32]byte, parts map[transferlink.Range][]byte) {
	r.T.Helper()
	s, state, err := r.Root.OpenChunkStaging(local, r.Key(local), sum, false, true)
	if err != nil || state != transferlocal.ChunkCreated {
		r.T.Fatalf("seed: OpenChunkStaging = %v, %v", state, err)
	}
	for rg, data := range parts {
		w, err := s.CreatePart(rg)
		if err != nil {
			r.T.Fatalf("seed: CreatePart: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			r.T.Fatalf("seed: Write: %v", err)
		}
		if err := w.Commit(); err != nil {
			r.T.Fatalf("seed: Commit: %v", err)
		}
	}
}

// Seed stores correct parts of content.
func (r *DlRig) Seed(local string, content []byte, ranges ...transferlink.Range) {
	r.T.Helper()
	r.SeedWith(local, sha256.Sum256(content), SeedParts(content, ranges...))
}

// Kept lists the parts the staging directory of local holds, after checking
// that nothing but the marker and finished parts is in it.
func (r *DlRig) Kept(local string, content []byte) []transferlink.Range {
	r.T.Helper()
	dir := r.StageDir(local)
	entries, err := os.ReadDir(dir)
	if err != nil {
		r.T.Fatalf("staging directory: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name != "marker" && !strings.HasPrefix(name, "part-") || strings.HasSuffix(name, ".tmp") {
			r.T.Fatalf("staging holds the stray entry %q", name)
		}
	}
	s, state, err := r.Root.OpenChunkStaging(local, r.Key(local), sha256.Sum256(content), false, false)
	if err != nil || state != transferlocal.ChunkReused {
		r.T.Fatalf("kept: OpenChunkStaging = %v, %v", state, err)
	}
	parts, overflow, err := s.ListParts(int64(len(content)), 1<<20)
	if err != nil || overflow {
		r.T.Fatalf("kept: ListParts = %v %v", overflow, err)
	}
	return parts
}

func (r *DlRig) AssertDownloaded(local string, want []byte) {
	r.T.Helper()
	got, err := os.ReadFile(r.LocalPath(local))
	if err != nil || !bytes.Equal(got, want) {
		r.T.Fatalf("%s is not downloaded byte-exact (err=%v)", local, err)
	}
	testfixture.NoStagingLeft(r.T, filepath.Dir(r.LocalPath(local)))
}

func (r *DlRig) AssertAbsent(local string) {
	r.T.Helper()
	if _, err := os.Lstat(r.LocalPath(local)); !os.IsNotExist(err) {
		r.T.Fatalf("%s exists (err=%v)", local, err)
	}
}

// StaleStage creates a keyed staging directory in the directory of local, with
// the pre-hash of content and a marker last touched age ago.
func (r *DlRig) StaleStage(local string, content []byte, age time.Duration, n int) string {
	r.T.Helper()
	key := fmt.Sprintf("%032x", n)
	s, state, err := r.Root.OpenChunkStaging(local, key, sha256.Sum256(content), false, true)
	if err != nil || state != transferlocal.ChunkCreated {
		r.T.Fatalf("staleStage: %v, %v", state, err)
	}
	dir := filepath.Join(filepath.Dir(r.LocalPath(local)), ".ssjack-transfer-"+key)
	old := time.Now().Add(-age)
	if err := os.Chtimes(filepath.Join(dir, "marker"), old, old); err != nil {
		r.T.Fatal(err)
	}
	_ = s
	return dir
}
