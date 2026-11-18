package probe

import (
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

func TestParseChunkLine(t *testing.T) {
	good := map[string]core.ChunkCaps{
		"SSJACK-CHUNK yes dd c yes":     {Own: true, Read: core.ReadDD, Mtime: core.MtimeGNU, DF: true},
		"SSJACK-CHUNK yes tail f no":    {Own: true, Read: core.ReadTail, Mtime: core.MtimeBSD},
		"SSJACK-CHUNK no none none no":  {Read: core.ReadNone, Mtime: core.MtimeNone},
		"SSJACK-CHUNK yes none none no": {Own: true, Read: core.ReadNone, Mtime: core.MtimeNone},
	}
	for line, want := range good {
		got, ok := parseChunkLine(line)
		if !ok || got != want {
			t.Errorf("parseChunkLine(%q) = %+v, %v; want %+v, true", line, got, ok, want)
		}
	}
	bad := []string{
		"", "SSJACK-CHUNK", "SSJACK-CHUNK yes dd c", "SSJACK-CHUNK yes dd c yes extra", "SSJACK-CHUNK  yes dd c yes",
		"SSJACK-CHUNK 1 dd c yes", "SSJACK-CHUNK Yes dd c yes", "SSJACK-CHUNK yes DD c yes", "SSJACK-CHUNK yes cat c yes",
		"SSJACK-CHUNK yes dd gnu yes", "SSJACK-CHUNK yes dd c true", "SSJACK-CAPS yes dd c yes", "SSJACK-CHUNK yes dd c yes\n",
		"SSJACK-CHUNK yes dd\tc yes",
	}
	for _, line := range bad {
		if got, ok := parseChunkLine(line); ok {
			t.Errorf("parseChunkLine(%q) = %+v, true; want rejection", line, got)
		}
	}
}

func TestChunkCapsAvailability(t *testing.T) {
	full := core.ChunkCaps{Own: true, Read: core.ReadDD, Mtime: core.MtimeBSD, DF: true}
	if !full.Upload() || !full.Download() {
		t.Fatalf("full caps must allow both directions: %+v", full)
	}
	cases := []struct {
		name     string
		caps     core.ChunkCaps
		up, down bool
	}{
		{"no own", core.ChunkCaps{Read: core.ReadDD, Mtime: core.MtimeGNU, DF: true}, false, false},
		{"no read", core.ChunkCaps{Own: true, Read: core.ReadNone, Mtime: core.MtimeGNU}, true, false},
		{"no mtime", core.ChunkCaps{Own: true, Read: core.ReadTail, Mtime: core.MtimeNone}, true, false},
		{"zero value", core.ChunkCaps{Own: true}, true, false},
		{"no df only", core.ChunkCaps{Own: true, Read: core.ReadTail, Mtime: core.MtimeGNU}, true, true},
	}
	for _, tc := range cases {
		if tc.caps.Upload() != tc.up || tc.caps.Download() != tc.down {
			t.Errorf("%s: Upload/Download = %v/%v, want %v/%v", tc.name, tc.caps.Upload(), tc.caps.Download(), tc.up, tc.down)
		}
	}
}

func TestParseProbeReport(t *testing.T) {
	const caps = "SSJACK-CAPS sha256sum t gnu names\n"
	t.Run("old output means chunking unavailable", func(t *testing.T) {
		got, ok := parseProbeReport(caps)
		if !ok || got.Hash != core.HashSha256sum || !got.MvT || !got.WcNames || got.Chunk != (core.ChunkCaps{}) {
			t.Fatalf("got %+v, %v", got, ok)
		}
	})
	t.Run("both lines", func(t *testing.T) {
		got, ok := parseProbeReport(caps + "SSJACK-CHUNK yes tail f yes\n")
		want := core.ChunkCaps{Own: true, Read: core.ReadTail, Mtime: core.MtimeBSD, DF: true}
		if !ok || got.Chunk != want || got.Hash != core.HashSha256sum {
			t.Fatalf("got %+v, %v", got, ok)
		}
	})
	t.Run("malformed chunk line is tolerated as unavailable", func(t *testing.T) {
		for _, tail := range []string{
			"SSJACK-CHUNK yes dd c\n",
			"SSJACK-CHUNK yes dd c maybe\n",
			"SSJACK-CHUNK yes dd c yes",
			"SSJACK-CHUNK yes dd c yes\nextra\n",
			"SSJACK-CHUNK yes dd c yes\nSSJACK-CHUNK yes dd c yes\n",
		} {
			got, ok := parseProbeReport(caps + tail)
			if !ok || got.Chunk != (core.ChunkCaps{}) || got.Hash != core.HashSha256sum {
				t.Errorf("tail %q: got %+v, %v; want caps with chunking unavailable", tail, got, ok)
			}
		}
	})
	t.Run("hostile trailers are rejected", func(t *testing.T) {
		for _, tail := range []string{
			"extra\n",
			"\n",
			"SSJACK-CHUNK\n",
			" SSJACK-CHUNK yes dd c yes\n",
			caps,
			"SSJACK-CHUNKS yes dd c yes\n",
			"ssjack-chunk yes dd c yes\n",
		} {
			if got, ok := parseProbeReport(caps + tail); ok {
				t.Errorf("tail %q accepted: %+v", tail, got)
			}
		}
	})
	t.Run("caps line stays strict", func(t *testing.T) {
		for _, report := range []string{
			"", "SSJACK-CHUNK yes dd c yes\n", "SSJACK-CHUNK yes dd c yes\n" + caps,
			"SSJACK-CAPS sha256sum t gnu names", "SSJACK-CAPS sha256sum t gnu\nSSJACK-CHUNK yes dd c yes\n",
			"SSJACK-CAPS sha256sum t gnu names extra\nSSJACK-CHUNK yes dd c yes\n",
		} {
			if got, ok := parseProbeReport(report); ok {
				t.Errorf("report %q accepted: %+v", report, got)
			}
		}
	})
}
