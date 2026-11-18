package transferremote

import "github.com/PHPCraftdream/ssjack/internal/transferremote/remotetest"

type fakeRunner = remotetest.FakeRunner

var (
	expectClass   = remotetest.ExpectClass
	expectCode    = remotetest.ExpectCode
	quotedIn      = remotetest.QuotedIn
	drainReader   = remotetest.DrainReader
	sampleLimits  = remotetest.SampleLimits
	testWantErr   = remotetest.WantErr
	testPayload   = remotetest.Payload
	testAsideName = remotetest.AsideName
)
