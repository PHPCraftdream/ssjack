package probe

import (
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

const (
	capsLinePrefix  = "SSJACK-CAPS"
	chunkLinePrefix = "SSJACK-CHUNK"
)

// parseCapsLine strictly parses the five-field `SSJACK-CAPS` line without its
// newline. The accepted values are unchanged from the original probe.
func parseCapsLine(line string) (core.Caps, bool) {
	fields := strings.Split(line, " ")
	if len(fields) != 5 || fields[0] != capsLinePrefix {
		return core.Caps{}, false
	}
	if (fields[1] != core.HashSha256sum && fields[1] != core.HashShasum && fields[1] != core.HashSha256q) ||
		(fields[2] != "t" && fields[2] != "p") || fields[3] != "gnu" ||
		(fields[4] != "names" && fields[4] != "stdin") {
		return core.Caps{}, false
	}
	return core.Caps{Hash: fields[1], MvT: fields[2] == "t", TarGNU: true, WcNames: fields[4] == "names"}, true
}

// parseChunkLine strictly parses `SSJACK-CHUNK <own> <read> <mtime> <df>`
// without its newline.
func parseChunkLine(line string) (core.ChunkCaps, bool) {
	fields := strings.Split(line, " ")
	if len(fields) != 5 || fields[0] != chunkLinePrefix {
		return core.ChunkCaps{}, false
	}
	var caps core.ChunkCaps
	switch fields[1] {
	case "yes":
		caps.Own = true
	case "no":
	default:
		return core.ChunkCaps{}, false
	}
	switch core.ReadMode(fields[2]) {
	case core.ReadDD, core.ReadTail, core.ReadNone:
		caps.Read = core.ReadMode(fields[2])
	default:
		return core.ChunkCaps{}, false
	}
	switch core.MtimeMode(fields[3]) {
	case core.MtimeGNU, core.MtimeBSD, core.MtimeNone:
		caps.Mtime = core.MtimeMode(fields[3])
	default:
		return core.ChunkCaps{}, false
	}
	switch fields[4] {
	case "yes":
		caps.DF = true
	case "no":
	default:
		return core.ChunkCaps{}, false
	}
	return caps, true
}

// parseProbeReport parses the whole probe output. The first line must be the
// original `SSJACK-CAPS` line. It is optionally followed by exactly one
// `SSJACK-CHUNK` line; old probe output (no second line) and a malformed
// `SSJACK-CHUNK` line both mean "chunking unavailable", never a refusal.
// Any other trailing text is rejected as before.
func parseProbeReport(report string) (core.Caps, bool) {
	nl := strings.IndexByte(report, '\n')
	if nl < 0 {
		return core.Caps{}, false
	}
	caps, ok := parseCapsLine(report[:nl])
	if !ok {
		return core.Caps{}, false
	}
	rest := report[nl+1:]
	switch {
	case rest == "":
	case strings.HasPrefix(rest, chunkLinePrefix+" "):
		if line, ok := strings.CutSuffix(rest, "\n"); ok {
			if chunk, ok := parseChunkLine(line); ok {
				caps.Chunk = chunk
			}
		}
	default:
		return core.Caps{}, false
	}
	return caps, true
}
