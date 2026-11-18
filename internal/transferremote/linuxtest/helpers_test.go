//go:build linux

package linuxtest

import "github.com/PHPCraftdream/ssjack/internal/transferremote/remotetest"

var (
	expectClass  = remotetest.ExpectClass
	expectCode   = remotetest.ExpectCode
	sampleLimits = remotetest.SampleLimits
	drainReader  = remotetest.DrainReader
	testPayload  = remotetest.Payload
)
