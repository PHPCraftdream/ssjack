package transferremote

import "strings"

// ReadMode names the verified range-read primitive of a remote host.
type ReadMode string

// MtimeMode names the verified stat flavour reporting size and mtime.
type MtimeMode string

const (
	// ReadNone means neither dd nor tail/head passed the functional probe.
	ReadNone ReadMode = "none"
	// ReadDD selects `dd if=FILE bs=S skip=I count=1`.
	ReadDD ReadMode = "dd"
	// ReadTail selects `tail -c +N | head -c L`.
	ReadTail ReadMode = "tail"

	// MtimeNone means no stat flavour passed the functional probe.
	MtimeNone MtimeMode = "none"
	// MtimeGNU selects `stat -c '%s %Y'` (GNU, uutils, BusyBox).
	MtimeGNU MtimeMode = "c"
	// MtimeBSD selects `stat -f '%z %m'` (BSD, macOS).
	MtimeBSD MtimeMode = "f"
)

// ChunkCaps is the chunked-mode verdict of the capability probe. A host that
// fails any of these is not unsupported_remote: it keeps the whole-stream
// behaviour and simply has no chunked mode (see Upload and Download).
type ChunkCaps struct {
	// Own: `test -O` and `find <path> -prune -type d -perm 0700` work, so
	// staging adoption and removal checks can run.
	Own bool
	// Read is the range-read primitive.
	Read ReadMode
	// Mtime is the stat flavour.
	Mtime MtimeMode
	// DF: `df -P -k` output parses, so the disk preflight can run.
	DF bool
}

// Upload reports whether chunked upload is available.
func (c ChunkCaps) Upload() bool { return c.Own }

// Download reports whether chunked download is available.
func (c ChunkCaps) Download() bool {
	return c.Own && (c.Read == ReadDD || c.Read == ReadTail) && (c.Mtime == MtimeGNU || c.Mtime == MtimeBSD)
}

const (
	capsLinePrefix  = "SSJACK-CAPS"
	chunkLinePrefix = "SSJACK-CHUNK"
)

// parseCapsLine strictly parses the five-field `SSJACK-CAPS` line without its
// newline. The accepted values are unchanged from the original probe.
func parseCapsLine(line string) (remoteCaps, bool) {
	fields := strings.Split(line, " ")
	if len(fields) != 5 || fields[0] != capsLinePrefix {
		return remoteCaps{}, false
	}
	if (fields[1] != hashSha256sum && fields[1] != hashShasum && fields[1] != hashSha256q) ||
		(fields[2] != "t" && fields[2] != "p") || fields[3] != "gnu" ||
		(fields[4] != "names" && fields[4] != "stdin") {
		return remoteCaps{}, false
	}
	return remoteCaps{hash: fields[1], mvT: fields[2] == "t", tarGNU: true, wcNames: fields[4] == "names"}, true
}

// parseChunkLine strictly parses `SSJACK-CHUNK <own> <read> <mtime> <df>`
// without its newline.
func parseChunkLine(line string) (ChunkCaps, bool) {
	fields := strings.Split(line, " ")
	if len(fields) != 5 || fields[0] != chunkLinePrefix {
		return ChunkCaps{}, false
	}
	var caps ChunkCaps
	switch fields[1] {
	case "yes":
		caps.Own = true
	case "no":
	default:
		return ChunkCaps{}, false
	}
	switch ReadMode(fields[2]) {
	case ReadDD, ReadTail, ReadNone:
		caps.Read = ReadMode(fields[2])
	default:
		return ChunkCaps{}, false
	}
	switch MtimeMode(fields[3]) {
	case MtimeGNU, MtimeBSD, MtimeNone:
		caps.Mtime = MtimeMode(fields[3])
	default:
		return ChunkCaps{}, false
	}
	switch fields[4] {
	case "yes":
		caps.DF = true
	case "no":
	default:
		return ChunkCaps{}, false
	}
	return caps, true
}

// parseProbeReport parses the whole probe output. The first line must be the
// original `SSJACK-CAPS` line. It is optionally followed by exactly one
// `SSJACK-CHUNK` line; old probe output (no second line) and a malformed
// `SSJACK-CHUNK` line both mean "chunking unavailable", never a refusal.
// Any other trailing text is rejected as before.
func parseProbeReport(report string) (remoteCaps, bool) {
	nl := strings.IndexByte(report, '\n')
	if nl < 0 {
		return remoteCaps{}, false
	}
	caps, ok := parseCapsLine(report[:nl])
	if !ok {
		return remoteCaps{}, false
	}
	rest := report[nl+1:]
	switch {
	case rest == "":
	case strings.HasPrefix(rest, chunkLinePrefix+" "):
		if line, ok := strings.CutSuffix(rest, "\n"); ok {
			if chunk, ok := parseChunkLine(line); ok {
				caps.chunk = chunk
			}
		}
	default:
		return remoteCaps{}, false
	}
	return caps, true
}
