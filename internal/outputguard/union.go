package outputguard

// Union retains every literal in both capabilities without exposing patterns.
// Duplicate literals count once; any bound violation refuses the whole union.
func Union(a, b *Snapshot) (*Snapshot, error) {
	if a == nil || b == nil || !a.valid || !b.valid {
		return nil, ErrGuard
	}
	s := &Snapshot{nodes: []node{{}}}
	for _, source := range []*Snapshot{a, b} {
		type pair struct{ source, destination int }
		queue := []pair{{}}
		for index := 0; index < len(queue); index++ {
			current := queue[index]
			s.nodes[current.destination].length = max(s.nodes[current.destination].length, source.nodes[current.source].length)
			for value, child := range source.nodes[current.source].edges {
				next, exists := s.nodes[current.destination].edges[value]
				if !exists {
					if len(s.nodes) == MaxNodes {
						return nil, ErrGuard
					}
					next = len(s.nodes)
					s.nodes = append(s.nodes, node{})
					if s.nodes[current.destination].edges == nil {
						s.nodes[current.destination].edges = make(map[byte]int)
					}
					s.nodes[current.destination].edges[value] = next
				}
				queue = append(queue, pair{child, next})
			}
		}
	}
	count, total := 0, 0
	for _, node := range s.nodes {
		if node.length != 0 {
			count++
			total += node.length
			s.longest = max(s.longest, node.length)
			if count > MaxPatterns || total > MaxPatternBytes {
				return nil, ErrGuard
			}
		}
	}
	s.link()
	s.valid = true
	return s, nil
}
