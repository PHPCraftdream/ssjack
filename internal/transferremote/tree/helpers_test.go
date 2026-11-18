package tree

import (
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/fileops"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/probe"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/remotetest"
)

type fakeRunner = remotetest.FakeRunner

var (
	expectClass  = remotetest.ExpectClass
	expectCode   = remotetest.ExpectCode
	sampleLimits = remotetest.SampleLimits
	testWantErr  = remotetest.WantErr
)

func newRemote(run remote.StreamRunner, target string, limits transfercore.Limits) *TreeOps {
	return New(core.NewRunner(run, target, limits))
}

// remoteRunner is the operation sets the portable listing tests drive over
// one core.Runner.
type remoteRunner struct {
	*core.Runner
	*probe.Prober
	*fileops.FileOps
	*TreeOps
}

func newRemoteFull(run remote.StreamRunner, target string, limits transfercore.Limits) *remoteRunner {
	r := core.NewRunner(run, target, limits)
	return &remoteRunner{Runner: r, Prober: probe.New(r), FileOps: fileops.New(r), TreeOps: New(r)}
}
