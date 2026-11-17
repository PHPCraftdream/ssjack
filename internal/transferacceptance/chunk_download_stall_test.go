//go:build linux || darwin

package transferacceptance

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/faultproxy"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
)

// The stall scenario of the chunked download is the mirror of the upload one
// (chunk_hardening_test.go): the same rig and the same short inactivity limit,
// with the freeze on the SERVER to CLIENT direction, which is where the payload
// of a download travels.

// stallEngine returns an engine with an empty link profile and the given stall
// limit, over the hooked chunk layer of the download rig.
func (r *downloadRig) stallEngine(limit time.Duration) *transferengine.Engine {
	r.t.Helper()
	engine, err := transferengine.NewWithOptions(r.hook, r.limits, transferengine.Options{Target: targetName, StallLimit: limit})
	if err != nil {
		r.t.Fatal(err)
	}
	return engine
}

// stallNextDown freezes the next connection after exactly n server-to-client
// bytes: the socket stays open and nothing more crosses it.
func (r *downloadRig) stallNextDown(n int64) {
	r.proxy.MustSetRules(r.t, faultproxy.Rule{
		Conns:  faultproxy.Conns(r.nextConn()),
		Faults: []faultproxy.Fault{faultproxy.StallAfterBytes(faultproxy.ServerToClient, n)},
	})
}

// scenarioChunkDownloadStallDetectedAndResumed freezes a connection mid-payload
// without closing it: no byte moves and no reset arrives, so only the stall
// watchdog can notice. With a short inactivity limit the stalled session is
// counted as a drop and the job goes on chunked and publishes byte-exact, for
// the whole-stream attempt and for a range read alike.
func scenarioChunkDownloadStallDetectedAndResumed(t *testing.T) {
	t.Run("stalled stream", func(t *testing.T) {
		rig := newDownloadRig(t)
		payload := SeedPayload(downloadPayload, 81)
		src := rig.source("blob.bin", payload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		rig.hook.onStream = func(n int) {
			if n == 1 {
				rig.stallNextDown(streamCutDown)
			}
		}

		start := time.Now()
		res, err := rig.download(rig.stallEngine(stallScenarioLimit), src, "got/blob.bin")
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("download after a stalled stream: %v", err)
		}
		assertDownloaded(t, res, dest, payload)
		if elapsed < stallScenarioLimit {
			t.Fatalf("download finished in %s, before the %s inactivity limit could have fired", elapsed, stallScenarioLimit)
		}
		if res.Mode != transferengine.ModeChunked || res.ChunksDone < 2 || res.ChunksTotal != res.ChunksDone || res.Attempts < 1+res.ChunksDone+1 {
			t.Fatalf("chunked telemetry = %+v", res)
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		assertSourceUntouched(t, src, payload)
		streams, stats, ranges := rig.hook.counts()
		if streams != 1 || ranges != res.ChunksDone || stats != ranges+2 {
			t.Fatalf("sessions: %d streams, %d source looks, %d range reads; result %+v", streams, stats, ranges, res)
		}
		proxyStats := rig.proxy.Stats()
		stalled := stalledConns(proxyStats)
		if len(stalled) != 1 || stalled[0].ServerToClient != streamCutDown || proxyStats.Dropped != 0 {
			t.Fatalf("proxy stats = %+v, want exactly one connection frozen at %d bytes and none cut", proxyStats, streamCutDown)
		}
	})
	t.Run("stalled part", func(t *testing.T) {
		rig := newDownloadRig(t)
		payload := SeedPayload(downloadPayload, 82)
		src := rig.source("blob.bin", payload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		rig.hook.onStream = func(n int) {
			if n == 1 {
				rig.cutNextDown(streamCutDown)
			}
		}
		rig.hook.onRange = func(n int, part transferlink.Range) {
			if n == 2 {
				rig.stallNextDown(partCutDown)
			}
		}

		start := time.Now()
		res, err := rig.download(rig.stallEngine(stallScenarioLimit), src, "got/blob.bin")
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("download with a stalled part: %v", err)
		}
		assertDownloaded(t, res, dest, payload)
		if elapsed < stallScenarioLimit {
			t.Fatalf("download finished in %s, before the %s inactivity limit could have fired", elapsed, stallScenarioLimit)
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		assertSourceUntouched(t, src, payload)
		calls := rig.hook.rangeCalls()
		if len(calls) < 3 || calls[1].part.Off != calls[0].part.End() || calls[2].part.Off != calls[1].part.Off {
			t.Fatalf("range reads = %v, want the stalled part read again from its own offset", calls)
		}
		if res.Mode != transferengine.ModeChunked || res.ChunksDone != len(calls)-1 {
			t.Fatalf("%d parts done after %d range reads, want exactly the stalled one lost (%+v)", res.ChunksDone, len(calls), res)
		}
		proxyStats := rig.proxy.Stats()
		stalled := stalledConns(proxyStats)
		if len(stalled) != 1 || stalled[0].ServerToClient != partCutDown {
			t.Fatalf("proxy stats = %+v, want exactly one part connection frozen at %d bytes", proxyStats, partCutDown)
		}
		cuts := cutConns(proxyStats)
		if len(cuts) != 1 || cuts[0].ServerToClient != streamCutDown {
			t.Fatalf("cut connections = %+v, want only the stream, cut at %d bytes", cuts, streamCutDown)
		}
	})
}
