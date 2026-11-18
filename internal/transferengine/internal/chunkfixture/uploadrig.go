package chunkfixture

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// ChunkRig is one engine over the in-memory chunk remote with a virtual
// clock: no test here sleeps or waits on a real timer.
type ChunkRig struct {
	T      *testing.T
	Clock  *testfixture.VClock
	Fake   *testfixture.FakeChunkRemote
	Engine *transferengine.Engine
	Root   *transferlocal.Root
}

func NewChunkRig(t *testing.T) *ChunkRig {
	t.Helper()
	clock := testfixture.NewVClock()
	rig := &ChunkRig{T: t, Clock: clock, Fake: testfixture.NewFakeChunkRemote(clock), Root: enginetest.TestRoot(t)}
	rig.Engine = rig.FreshEngine()
	return rig
}

// FreshEngine returns an engine of the same target with an empty link
// profile: a new keeper process.
func (r *ChunkRig) FreshEngine() *transferengine.Engine {
	r.T.Helper()
	profile := transferlink.NewProfile(transferlink.Config{Now: r.Clock.Now})
	engine, err := transferengine.NewWithOptions(r.Fake, transfercore.DefaultLimits(), transferengine.Options{Target: "t1", Profile: profile, Now: r.Clock.Now})
	if err != nil {
		r.T.Fatalf("NewWithOptions: %v", err)
	}
	return engine
}

func (r *ChunkRig) Write(rel string, content []byte) string {
	return testfixture.WriteLocalFile(r.T, r.Root, rel, content)
}

// Key is the staging key the engine derives for the current state of rel.
func (r *ChunkRig) Key(rel, remote string) string {
	r.T.Helper()
	info, err := os.Stat(filepath.Join(r.Root.Dir(), filepath.FromSlash(rel)))
	if err != nil {
		r.T.Fatal(err)
	}
	return transferremote.StagingKey("t1", remote, rel, strconv.FormatInt(info.Size(), 10), strconv.FormatInt(info.ModTime().UnixNano(), 10))
}

func (r *ChunkRig) Upload(engine *transferengine.Engine, rel, remote string, overwrite bool) (transferengine.Result, error, *ProgressLog) {
	log := &ProgressLog{}
	res, err := engine.Upload(context.Background(), r.Root, rel, remote, overwrite, log.Add)
	return res, err, log
}

func AssertPublished(t *testing.T, fake *testfixture.FakeChunkRemote, dest string, want []byte) {
	t.Helper()
	got, ok := fake.Get(dest)
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("%s is not published byte-exact (present=%v)", dest, ok)
	}
}

func AssertNotPublished(t *testing.T, fake *testfixture.FakeChunkRemote, dest string) {
	t.Helper()
	if _, ok := fake.Get(dest); ok {
		t.Fatalf("%s was published", dest)
	}
	if fake.PublishCount() != 0 {
		t.Fatalf("publication recorded %d times", fake.PublishCount())
	}
}

// AssertCleanRemote requires neither a chunk staging nor a stream staging.
func AssertCleanRemote(t *testing.T, fake *testfixture.FakeChunkRemote) {
	t.Helper()
	if n := fake.StageCount(); n != 0 {
		t.Fatalf("%d chunk staging directories left behind", n)
	}
	if n := fake.StagingCount(); n != 0 {
		t.Fatalf("%d stream staging directories left behind", n)
	}
}
