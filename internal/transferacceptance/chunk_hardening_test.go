//go:build linux || darwin

package transferacceptance

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/faultproxy"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
)

// The scenarios below harden the chunked upload: the stall watchdog turns a
// silent break into a drop, and a leftover assembled file is cleaned out of the
// staging directory. They use the same rig as the other chunked upload
// scenarios.

// stallScenarioLimit is the inactivity limit the stall scenario gives the
// engine. It is real time, short enough to keep the scenario quick and long
// enough that no healthy session on a loaded runner goes this long without
// moving a byte (a session moves bytes within milliseconds of its start).
const stallScenarioLimit = 5 * time.Second

// engineWithStall returns an engine with an empty link profile and the given
// stall limit.
func (r *uploadRig) engineWithStall(limit time.Duration) *transferengine.Engine {
	r.t.Helper()
	engine, err := transferengine.NewWithOptions(r.remote, r.limits, transferengine.Options{Target: targetName, StallLimit: limit})
	if err != nil {
		r.t.Fatal(err)
	}
	return engine
}

// stallNext freezes the next connection after exactly n client-to-server bytes:
// the socket stays open and nothing more crosses it.
func (r *uploadRig) stallNext(n int64) {
	r.proxy.MustSetRules(r.t, faultproxy.Rule{
		Conns:  faultproxy.Conns(r.nextConn()),
		Faults: []faultproxy.Fault{faultproxy.StallAfterBytes(faultproxy.ClientToServer, n)},
	})
}

func stalledConns(stats faultproxy.Stats) []faultproxy.ConnStats {
	var stalled []faultproxy.ConnStats
	for _, conn := range stats.Conns {
		if conn.Stalled {
			stalled = append(stalled, conn)
		}
	}
	return stalled
}

// scenarioChunkUploadStallDetectedAndResumed freezes a connection mid-payload
// without closing it: no byte moves and no reset arrives, so only the stall
// watchdog can notice. With a short inactivity limit the stalled session is
// counted as a drop and the job goes on chunked and publishes byte-exact, for
// the whole-stream attempt and for a part session alike.
func scenarioChunkUploadStallDetectedAndResumed(t *testing.T) {
	t.Run("stalled stream", func(t *testing.T) {
		rig := newUploadRig(t)
		payload := SeedPayload(uploadPayload, 61)
		rig.seed("big/blob.bin", payload)
		parent := rig.dir("in")
		dest := parent + "/blob.bin"
		rig.remote.onStream = func(n int) {
			if n == 1 {
				rig.stallNext(streamCut)
			}
		}

		start := time.Now()
		res, err := rig.upload(rig.engineWithStall(stallScenarioLimit), "big/blob.bin", dest)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("upload after a stalled stream: %v", err)
		}
		assertUploaded(t, res, dest, payload)
		if elapsed < stallScenarioLimit {
			t.Fatalf("upload finished in %s, before the %s inactivity limit could have fired", elapsed, stallScenarioLimit)
		}
		if res.Mode != transferengine.ModeChunked || res.ChunksDone < 2 || res.Attempts < 1+res.ChunksDone+1 {
			t.Fatalf("chunked telemetry = %+v", res)
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		streams, parts, assembles := rig.remote.counts()
		if streams != 1 || parts != res.ChunksDone || assembles != 1 {
			t.Fatalf("sessions: %d streams, %d parts, %d assemblies; result %+v", streams, parts, assembles, res)
		}
		stats := rig.proxy.Stats()
		stalled := stalledConns(stats)
		if len(stalled) != 1 || stalled[0].ClientToServer != streamCut || stats.Dropped != 0 {
			t.Fatalf("proxy stats = %+v, want exactly one connection frozen at %d bytes and none cut", stats, streamCut)
		}
	})
	t.Run("stalled part", func(t *testing.T) {
		rig := newUploadRig(t)
		payload := SeedPayload(uploadPayload, 62)
		rig.seed("big/blob.bin", payload)
		parent := rig.dir("in")
		dest := parent + "/blob.bin"
		rig.remote.onStream = func(n int) {
			if n == 1 {
				rig.cutNext(streamCut)
			}
		}
		rig.remote.onPart = func(n int, part transferlink.Range) {
			if n == 2 {
				rig.stallNext(partCut)
			}
		}

		start := time.Now()
		res, err := rig.upload(rig.engineWithStall(stallScenarioLimit), "big/blob.bin", dest)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("upload with a stalled part: %v", err)
		}
		assertUploaded(t, res, dest, payload)
		if elapsed < stallScenarioLimit {
			t.Fatalf("upload finished in %s, before the %s inactivity limit could have fired", elapsed, stallScenarioLimit)
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		ranges := rig.remote.ranges()
		if len(ranges) < 3 || ranges[1].Off != ranges[0].End() || ranges[2].Off != ranges[1].Off {
			t.Fatalf("part sessions = %v, want the stalled part sent again from its own offset", ranges)
		}
		if res.Mode != transferengine.ModeChunked || res.ChunksDone != len(ranges)-1 {
			t.Fatalf("%d parts done after %d part sessions, want exactly the stalled one lost (%+v)", res.ChunksDone, len(ranges), res)
		}
		stats := rig.proxy.Stats()
		stalled := stalledConns(stats)
		if len(stalled) != 1 || stalled[0].ClientToServer != partCut {
			t.Fatalf("proxy stats = %+v, want exactly one part connection frozen at %d bytes", stats, partCut)
		}
		cuts := cutConns(stats)
		if len(cuts) != 1 || cuts[0].ClientToServer != streamCut {
			t.Fatalf("cut connections = %+v, want only the stream, cut at %d bytes", cuts, streamCut)
		}
	})
}

// scenarioChunkUploadLeftoverAssemblyCleaned plants full-size leftover
// assembled files, as a killed assembly leaves them, in the staging directory
// of a stranded upload. A listing removes exactly those and reports them, and
// the resumed upload finds the directory clean before it sends a part or
// assembles, then completes byte-exact.
func scenarioChunkUploadLeftoverAssemblyCleaned(t *testing.T) {
	rig := newUploadRig(t)
	payload := SeedPayload(uploadPayload, 63)
	rig.seed("big/blob.bin", payload)
	parent := rig.dir("in")
	dest := parent + "/blob.bin"
	staging := rig.strandUpload("big/blob.bin", dest)
	key := strings.TrimPrefix(filepath.Base(staging), ".ssjack-transfer-")
	before := stagedParts(t, staging)

	leftovers := []string{"assembled.0123456789abcdef.tmp", "assembled.fedcba9876543210.tmp"}
	// A name that is not an assembly's random suffix is not ours to remove.
	const decoy = "assembled.keep-this-one.tmp"
	plant := func() {
		t.Helper()
		for _, name := range leftovers {
			writeFile(t, filepath.Join(staging, name), payload)
		}
		writeFile(t, filepath.Join(staging, decoy), []byte("decoy"))
	}
	requireClean := func(when string) {
		t.Helper()
		for _, name := range leftovers {
			if exists(filepath.Join(staging, name)) {
				t.Errorf("%s: leftover %s is still in the staging directory", when, name)
			}
		}
		if !exists(filepath.Join(staging, decoy)) {
			t.Errorf("%s: %s was removed, but it is not an assembly leftover", when, decoy)
		}
		// The parts found on resume are never touched (parts sent since then
		// may have been added).
		for _, part := range before {
			if !exists(partFile(staging, part)) {
				t.Errorf("%s: part %+v disappeared", when, part)
			}
		}
	}

	// The remote layer on its own: the listing removes and reports the
	// leftovers, and the parts are untouched.
	plant()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	listing, err := rig.remote.ListStaging(ctx, parent, key, int64(len(payload)))
	if err != nil {
		t.Fatalf("ListStaging: %v", err)
	}
	if listing.StaleAssembled != len(leftovers) || listing.Overflow || len(listing.Remove) != 0 || len(listing.Parts) != len(before) {
		t.Fatalf("listing = %+v, want %d leftovers removed and %d parts kept", listing, len(leftovers), len(before))
	}
	requireClean("after ListStaging")
	again, err := rig.remote.ListStaging(ctx, parent, key, int64(len(payload)))
	if err != nil || again.StaleAssembled != 0 {
		t.Fatalf("second listing = %+v, %v; want nothing left to remove", again, err)
	}

	// The engine: the planted files are gone before the first part is sent and
	// before the assembly starts.
	plant()
	var mu sync.Mutex
	var checks []string
	rig.remote.reset()
	rig.remote.onPart = func(n int, part transferlink.Range) {
		if n == 1 {
			mu.Lock()
			checks = append(checks, "first part")
			mu.Unlock()
			requireClean("before the first part")
		}
	}
	rig.remote.onAssemble = func(n int) {
		if n == 1 {
			mu.Lock()
			checks = append(checks, "assembly")
			mu.Unlock()
			requireClean("before the assembly")
		}
	}
	res, err := rig.upload(rig.engine(), "big/blob.bin", dest)
	if err != nil {
		t.Fatalf("resumed upload with leftovers in the staging: %v", err)
	}
	assertUploaded(t, res, dest, payload)
	mu.Lock()
	ran := strings.Join(checks, ",")
	mu.Unlock()
	if ran != "first part,assembly" {
		t.Fatalf("checks that ran = %q, want the first part and the assembly", ran)
	}
	streams, _, assembles := rig.remote.counts()
	if streams != 0 || assembles != 1 {
		t.Fatalf("resume ran %d streams and %d assemblies", streams, assembles)
	}
	if exists(staging) {
		t.Fatal("the upload left its staging behind")
	}
	assertOnlyEntries(t, parent, "blob.bin")
	rig.assertNoStaging(parent)
}
