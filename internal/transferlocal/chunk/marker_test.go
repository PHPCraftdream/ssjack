package chunk

import (
	"fmt"
	"strings"
	"testing"
)

func chunkSum(b byte) [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = b
	}
	return s
}

func chunkKey(n int) string { return fmt.Sprintf("%032x", n) }

func TestChunkMarkerFormat(t *testing.T) {
	key := chunkKey(40)
	text := FormatMarker(key, chunkSum(0xab))
	m, ok := parseChunkMarker(text)
	if !ok || m.key != key || m.sum != chunkSum(0xab) {
		t.Fatalf("round trip = %+v, %v", m, ok)
	}
	for _, bad := range []string{
		"", "SSJACK-STAGING 1 " + key + "\n",
		strings.TrimSuffix(text, "\n"),
		text + "extra\n",
		strings.Replace(text, "SSJACK-STAGING 1", "SSJACK-STAGING 2", 1),
		strings.Replace(text, "SSJACK-SOURCE-SHA256 ", "SSJACK-SOURCE-SHA256 zz", 1),
		strings.Replace(text, key, strings.ToUpper(chunkKey(255)), 1),
	} {
		if _, ok := parseChunkMarker(bad); ok {
			t.Fatalf("marker %q was accepted", bad)
		}
	}
}
