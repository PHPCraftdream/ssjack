package watchdog

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
)

// errWriter is a sink that refuses every write.
type errWriter struct{ err error }

func (e errWriter) Write([]byte) (int, error) { return 0, e.err }

func TestStallWriterCountsAcceptedBytes(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, _ := NewConfig(clock, time.Minute)
	wd, ctx := cfg.Start(context.Background())
	var sink bytes.Buffer
	w := &stallWriter{w: &sink, s: wd}
	// A slow but moving link: every buffer arrives just under the limit apart.
	for i := 0; i < 10; i++ {
		clock.Advance(time.Minute - time.Nanosecond)
		if n, err := w.Write(make([]byte, 100)); n != 100 || err != nil {
			t.Fatalf("write %d = %d, %v", i, n, err)
		}
	}
	requireDone(t, ctx, false)
	if sink.Len() != 1000 {
		t.Fatalf("the sink got %d bytes, want 1000", sink.Len())
	}
	// Nothing more arrives.
	clock.Advance(time.Minute)
	requireDone(t, ctx, true)
	if !wd.Stop() {
		t.Fatal("a silent link was not reported as a stall")
	}
}

func TestStallWriterIgnoresARefusedWrite(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, _ := NewConfig(clock, time.Minute)
	wd, ctx := cfg.Start(context.Background())
	boom := errors.New("boom")
	w := &stallWriter{w: errWriter{boom}, s: wd}
	clock.Advance(time.Minute - time.Nanosecond)
	if n, err := w.Write(make([]byte, 100)); n != 0 || !errors.Is(err, boom) {
		t.Fatalf("write = %d, %v, want the sink's own error", n, err)
	}
	// The refused write did not re-arm the timer.
	requireDone(t, ctx, false)
	clock.Advance(time.Nanosecond)
	requireDone(t, ctx, true)
	if !wd.Stop() {
		t.Fatal("the stall was lost")
	}
}

func TestStallWriterPassesDataThrough(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, _ := NewConfig(clock, time.Minute)
	wd, _ := cfg.Start(context.Background())
	defer wd.Stop()
	var sink bytes.Buffer
	want := []byte("payload")
	if n, err := (&stallWriter{w: &sink, s: wd}).Write(want); n != len(want) || err != nil || !bytes.Equal(sink.Bytes(), want) {
		t.Fatalf("write = %d, %v, sink %q", n, err, sink.Bytes())
	}
}
