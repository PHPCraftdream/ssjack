// Package outputguard masks known byte literals without exposing their values.
package outputguard

import "errors"

const (
	Marker          = "[REDACTED]"
	MaxPatterns     = 1024
	MaxPatternBytes = 1 << 20
	MaxPatternSize  = 64 << 10
	MaxNodes        = 128 << 10
)

var ErrGuard = errors.New("MCP output guard unavailable")

type node struct {
	edges  map[byte]int
	fail   int
	output int
	length int
}

// Snapshot is immutable. It retains no caller buffers and has no value getter.
type Snapshot struct {
	nodes   []node
	longest int
	valid   bool
}

func New(patterns [][]byte) (*Snapshot, error) {
	if len(patterns) > MaxPatterns {
		return nil, ErrGuard
	}
	s := &Snapshot{nodes: []node{{}}}
	total := 0
	for _, pattern := range patterns {
		if len(pattern) > MaxPatternSize || len(pattern) > MaxPatternBytes-total {
			return nil, ErrGuard
		}
		total += len(pattern)
		if len(pattern) == 0 {
			continue
		}
		current := 0
		for _, b := range pattern {
			next, ok := s.nodes[current].edges[b]
			if !ok {
				if len(s.nodes) == MaxNodes {
					return nil, ErrGuard
				}
				next = len(s.nodes)
				s.nodes = append(s.nodes, node{})
				if s.nodes[current].edges == nil {
					s.nodes[current].edges = make(map[byte]int)
				}
				s.nodes[current].edges[b] = next
			}
			current = next
		}
		s.nodes[current].length = len(pattern)
		s.longest = max(s.longest, len(pattern))
	}
	s.link()
	s.valid = true
	return s, nil
}

func (s *Snapshot) link() {
	queue := make([]int, 0, len(s.nodes))
	for _, child := range s.nodes[0].edges {
		queue = append(queue, child)
	}
	for index := 0; index < len(queue); index++ {
		current := queue[index]
		for b, child := range s.nodes[current].edges {
			failure := s.advance(s.nodes[current].fail, b)
			s.nodes[child].fail = failure
			if s.nodes[failure].length != 0 {
				s.nodes[child].output = failure
			} else {
				s.nodes[child].output = s.nodes[failure].output
			}
			queue = append(queue, child)
		}
	}
}

func (s *Snapshot) advance(current int, b byte) int {
	for {
		if next, ok := s.nodes[current].edges[b]; ok {
			return next
		}
		if current == 0 {
			return 0
		}
		current = s.nodes[current].fail
	}
}
