package core

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

// Hash variants of the probe verdict.
const (
	HashSha256sum = "sha256sum"
	HashShasum    = "shasum"
	HashSha256q   = "sha256q"
)

// Caps is the functional probe verdict for one remote host.
type Caps struct {
	Hash   string // "sha256sum", "shasum" or "sha256q"
	MvT    bool   // mv -T is functional; false selects Perl rename/link
	TarGNU bool   // tar -x --no-same-owner --no-same-permissions is functional
	// WcNames is functional; false selects the stdin-based portable size listing.
	WcNames bool
	// Chunk is the chunked-mode verdict; the zero value means unavailable.
	Chunk ChunkCaps
}
