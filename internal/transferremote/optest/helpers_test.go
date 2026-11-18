package optest

import (
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/remotetest"
)

type fakeRunner = remotetest.FakeRunner

var (
	expectClass    = remotetest.ExpectClass
	expectCode     = remotetest.ExpectCode
	quotedIn       = remotetest.QuotedIn
	drainReader    = remotetest.DrainReader
	sampleLimits   = remotetest.SampleLimits
	testWantErr    = remotetest.WantErr
	testExpectExit = remotetest.ExpectExit
	testPayload    = remotetest.Payload
	testAsideName  = remotetest.AsideName
)

// testExitCase is one remote-exit-code -> class expectation.
type testExitCase struct {
	code int
	want transfercore.Class
}
