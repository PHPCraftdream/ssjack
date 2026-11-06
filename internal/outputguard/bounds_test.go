package outputguard

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
)

func TestConstructionRefusesBoundsWithoutTruncatingPatterns(t *testing.T) {
	large := bytes.Repeat([]byte{'a'}, MaxPatternSize)
	for _, patterns := range [][][]byte{
		make([][]byte, MaxPatterns+1),
		{make([]byte, MaxPatternSize+1)},
		{large, bytes.Repeat([]byte{'b'}, MaxPatternSize)},
		bytesPatterns(large, MaxPatternBytes/MaxPatternSize+1),
	} {
		if snapshot, err := New(patterns); err != ErrGuard || snapshot != nil {
			t.Fatal("oversized matcher was silently truncated or admitted")
		}
	}
	snapshot, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if writer, err := NewWriter(nil, io.Discard); err != ErrGuard || writer != nil {
		t.Fatal("missing snapshot accepted an unguarded stream")
	}
	if writer, err := NewWriter(&Snapshot{}, io.Discard); err != ErrGuard || writer != nil {
		t.Fatal("zero snapshot accepted an unguarded stream")
	}
	if writer, err := NewWriter(snapshot, nil); err != ErrGuard || writer != nil {
		t.Fatal("missing destination accepted a stream")
	}
}

func bytesPatterns(pattern []byte, count int) [][]byte {
	patterns := make([][]byte, count)
	for i := range patterns {
		patterns[i] = pattern
	}
	return patterns
}

type failingGuardSink struct {
	short bool
}

func (s failingGuardSink) Write([]byte) (int, error) {
	if s.short {
		return 0, nil
	}
	return 0, errors.New("synthetic private downstream diagnostic")
}

func TestDownstreamFailurePoisonsStreamWithoutPrivateDiagnostics(t *testing.T) {
	for _, patterns := range [][][]byte{nil, {[]byte("secret")}} {
		for _, short := range []bool{false, true} {
			snapshot, err := New(patterns)
			if err != nil {
				t.Fatal(err)
			}
			writer, err := NewWriter(snapshot, failingGuardSink{short: short})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte("secret")); err != ErrGuard {
				t.Fatal("sink failure was hidden or leaked its private diagnostic")
			}
			for _, b := range writer.pending {
				if b != 0 {
					t.Fatal("failed stream retained private pending bytes")
				}
			}
			if writer.Close() != ErrGuard {
				t.Fatal("failed stream reported a successful close")
			}
			if _, err := writer.Write([]byte("retry")); err != ErrGuard {
				t.Fatal("failed stream permitted automatic continuation")
			}
		}
	}
}

func TestClosePropagatesFinalPrefixSinkFailure(t *testing.T) {
	snapshot, err := New([][]byte{[]byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewWriter(snapshot, failingGuardSink{})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write([]byte("secre")); n != 5 || err != nil {
		t.Fatal("prefix was not retained until explicit end")
	}
	if writer.Close() != ErrGuard || writer.Close() != ErrGuard {
		t.Fatal("final-tail failure did not remain visible")
	}
}

type boundedGuardSink struct {
	maximum int
	total   int
}

func (s *boundedGuardSink) Write(data []byte) (int, error) {
	s.maximum = max(s.maximum, len(data))
	s.total += len(data)
	if len(data)%len(Marker) != 0 || !bytes.Equal(data, bytes.Repeat([]byte(Marker), len(data)/len(Marker))) {
		return 0, errors.New("unexpected guard output")
	}
	return len(data), nil
}

func TestOneBytePatternsBoundExpansionAndEmissionBuffers(t *testing.T) {
	snapshot, err := New([][]byte{[]byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	sink := &boundedGuardSink{}
	writer, err := NewWriter(snapshot, sink)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{'a'}, 100000)
	if n, err := writer.Write(data); err != nil || n != len(data) || writer.Close() != nil {
		t.Fatal("bounded marker expansion failed")
	}
	if sink.total != len(data)*len(Marker) || sink.maximum > outputChunk+len(Marker) {
		t.Fatal("marker expansion or individual sink writes exceeded their bound")
	}
}

func TestIndependentStreamsShareAnImmutableSnapshot(t *testing.T) {
	snapshot, err := New([][]byte{[]byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Go(func() {
			var output bytes.Buffer
			writer, err := NewWriter(snapshot, &output)
			if err != nil {
				t.Error("immutable snapshot did not admit an independent stream")
				return
			}
			_, err = writer.Write([]byte("secret safe"))
			if err != nil || writer.Close() != nil || output.String() != Marker+" safe" {
				t.Error("independent stream changed snapshot or another stream's state")
			}
		})
	}
	workers.Wait()
}
