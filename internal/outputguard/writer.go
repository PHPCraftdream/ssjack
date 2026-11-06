package outputguard

import (
	"io"
	"math"
	"sync"
)

const outputChunk = 32 << 10

// Writer delays at most one maximum-length literal, never flushing on a timer.
// Close ends this stream, not its borrowed destination or immutable snapshot.
type Writer struct {
	mu       sync.Mutex
	snapshot *Snapshot
	sink     io.Writer
	pending  []byte
	matches  []int
	output   []byte
	base     int64
	end      int64
	state    int
	closed   bool
	failed   bool
}

func NewWriter(snapshot *Snapshot, destination io.Writer) (*Writer, error) {
	if snapshot == nil || !snapshot.valid || destination == nil {
		return nil, ErrGuard
	}
	return &Writer{snapshot: snapshot, sink: destination, pending: make([]byte, snapshot.longest), matches: make([]int, snapshot.longest)}, nil
}

func (w *Writer) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.snapshot == nil || w.closed || w.failed {
		return 0, ErrGuard
	}
	if len(w.pending) == 0 {
		for offset := 0; offset < len(data); {
			end := min(offset+outputChunk, len(data))
			n, err := w.sink.Write(data[offset:end])
			if err != nil || n != end-offset {
				w.poison()
				return offset, ErrGuard
			}
			offset = end
		}
		return len(data), nil
	}
	for index, b := range data {
		if w.end == math.MaxInt64 {
			w.poison()
			return index, ErrGuard
		}
		position := int(w.end % int64(len(w.pending)))
		w.pending[position], w.matches[position] = b, 0
		w.end++
		w.state = w.snapshot.advance(w.state, b)
		for state := w.state; state != 0; state = w.snapshot.nodes[state].output {
			length := w.snapshot.nodes[state].length
			start := w.end - int64(length)
			if length != 0 && start >= w.base {
				slot := int(start % int64(len(w.pending)))
				w.matches[slot] = max(w.matches[slot], length)
			}
		}
		if w.end-w.base >= int64(len(w.pending)) {
			w.resolve()
		}
		if len(w.output) >= outputChunk && !w.flush() {
			return index + 1, ErrGuard
		}
	}
	if !w.flush() {
		return len(data), ErrGuard
	}
	return len(data), nil
}

func (w *Writer) resolve() {
	slot := int(w.base % int64(len(w.pending)))
	length := w.matches[slot]
	if length != 0 {
		w.output = append(w.output, Marker...)
	} else {
		w.output = append(w.output, w.pending[slot])
		length = 1
	}
	for index := 0; index < length; index++ {
		slot = int((w.base + int64(index)) % int64(len(w.pending)))
		w.pending[slot], w.matches[slot] = 0, 0
	}
	w.base += int64(length)
}

func (w *Writer) flush() bool {
	if len(w.output) == 0 {
		return true
	}
	n, err := w.sink.Write(w.output)
	if err != nil || n != len(w.output) {
		w.poison()
		return false
	}
	clear(w.output)
	w.output = w.output[:0]
	return true
}

func (w *Writer) poison() {
	w.failed = true
	clear(w.pending)
	clear(w.matches)
	clear(w.output)
	w.output = nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.snapshot == nil || w.failed {
		return ErrGuard
	}
	if w.closed {
		return nil
	}
	w.closed = true
	for w.base < w.end {
		w.resolve()
		if len(w.output) >= outputChunk && !w.flush() {
			return ErrGuard
		}
	}
	if !w.flush() {
		return ErrGuard
	}
	clear(w.pending)
	clear(w.matches)
	w.pending, w.matches, w.output = nil, nil, nil
	return nil
}
