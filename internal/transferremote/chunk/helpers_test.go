package chunk

import (
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/probe"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/remotetest"
)

type fakeRunner = remotetest.FakeRunner

var (
	expectClass  = remotetest.ExpectClass
	expectCode   = remotetest.ExpectCode
	quotedIn     = remotetest.QuotedIn
	drainReader  = remotetest.DrainReader
	sampleLimits = remotetest.SampleLimits
	testWantErr  = remotetest.WantErr
)

// remoteRunner is the probe and chunk operations over one core.Runner.
type remoteRunner struct {
	*core.Runner
	*probe.Prober
	*ChunkOps
}

func newRemote(run remote.StreamRunner, target string, limits transfercore.Limits) *remoteRunner {
	r := core.NewRunner(run, target, limits)
	return &remoteRunner{Runner: r, Prober: probe.New(r), ChunkOps: New(r)}
}
