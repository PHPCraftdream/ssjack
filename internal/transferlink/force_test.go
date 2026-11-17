package transferlink

import "testing"

func TestForceChunkedSeedsTheChunkSize(t *testing.T) {
	p := newTestProfile(newClock())
	p.ForceChunked(400 << 10)
	snap := p.Snapshot()
	if snap.Mode != ModeChunked || snap.Stored != 400<<10 {
		t.Fatalf("snapshot after ForceChunked = %+v", snap)
	}
	step := p.Decide(10 * mb)
	if step.Mode != ModeChunked || step.Len != 400<<10 {
		t.Fatalf("Decide = %+v, want chunked 400 KiB", step)
	}
}

func TestForceChunkedClampsAndKeepsOnZero(t *testing.T) {
	p := newTestProfile(newClock())
	p.ForceChunked(1)
	if got := p.Snapshot().Stored; got != MinChunk {
		t.Fatalf("tiny seed stored %d, want %d", got, MinChunk)
	}
	p.ForceChunked(1 << 40)
	if got := p.Snapshot().Stored; got != MaxChunk {
		t.Fatalf("huge seed stored %d, want %d", got, MaxChunk)
	}
	p.ForceChunked(512 << 10)
	p.ForceChunked(0)
	snap := p.Snapshot()
	if snap.Mode != ModeChunked || snap.Stored != 512<<10 {
		t.Fatalf("seed 0 changed the stored size: %+v", snap)
	}
}

func TestForceChunkedReturnsToStreamForTheLastGap(t *testing.T) {
	p := newTestProfile(newClock())
	p.ForceChunked(400 << 10)
	step := p.Decide(300 << 10)
	if step.Mode != ModeStream || step.Len != 300<<10 {
		t.Fatalf("Decide(300 KiB) = %+v, want a stream of the remainder", step)
	}
}
