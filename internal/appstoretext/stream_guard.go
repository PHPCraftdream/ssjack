package appstoretext

import "bytes"

// The raw-input guard is independent of replacement skips and chunk boundaries.
type streamGuard struct {
	patterns [][]byte
	tail     []byte
	keep     int
}

func newStreamGuard(patterns [][]byte) streamGuard {
	keep := 0
	for _, pattern := range patterns {
		keep = max(keep, len(pattern)-1)
	}
	return streamGuard{patterns: patterns, tail: make([]byte, 0, 2*keep), keep: keep}
}

func (g *streamGuard) accept(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	g.tail = append(g.tail, data[:min(len(data), g.keep)]...)
	for _, pattern := range g.patterns {
		if bytes.Contains(data, pattern) || bytes.Contains(g.tail, pattern) {
			return ErrInvalid
		}
	}
	if len(data) >= g.keep {
		copy(g.tail[:g.keep], data[len(data)-g.keep:])
		g.tail = g.tail[:g.keep]
	} else if len(g.tail) > g.keep {
		copy(g.tail, g.tail[len(g.tail)-g.keep:])
		g.tail = g.tail[:g.keep]
	}
	clear(g.tail[len(g.tail):cap(g.tail)])
	return nil
}
