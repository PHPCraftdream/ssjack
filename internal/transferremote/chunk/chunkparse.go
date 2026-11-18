package chunk

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

// Fixed, content-free errors of the chunked output parsers.
const (
	msgChunkMalformed = "remote chunk output could not be parsed"
	msgChunkDuplicate = "remote part listing contains a duplicate entry"
	msgChunkRange     = "remote range read returned an unexpected length"
)

func chunkMalformed() *transfercore.Error {
	return core.ListingError(transfercore.ClassIntegrity, msgChunkMalformed)
}

// parseCanonical parses a canonical non-negative decimal: ASCII digits only,
// no sign, no padding, no leading zero except the single digit "0", at most
// int64.
func parseCanonical(s string) (int64, bool) {
	if s == "" || len(s) > 19 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// oneLine returns the single line of data, which must end in exactly one
// newline and contain no other.
func oneLine(data []byte) (string, bool) {
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		return "", false
	}
	s = strings.TrimSuffix(s, "\n")
	if strings.Contains(s, "\n") {
		return "", false
	}
	return s, true
}

// StagingState is the verdict of EnsureStaging.
type StagingState int

const (
	// StagingCreated: a fresh directory with its marker was created.
	StagingCreated StagingState = iota + 1
	// StagingReused: an existing directory passed every adoption check.
	StagingReused
	// StagingForeign: the path holds an object that failed an adoption
	// check; it was not used, written to or removed.
	StagingForeign
)

// parseStageEnsure parses `SSJACK-STAGE created|reused|foreign\n`.
func parseStageEnsure(data []byte) (StagingState, error) {
	line, ok := oneLine(data)
	if !ok {
		return 0, chunkMalformed()
	}
	switch line {
	case "SSJACK-STAGE created":
		return StagingCreated, nil
	case "SSJACK-STAGE reused":
		return StagingReused, nil
	case "SSJACK-STAGE foreign":
		return StagingForeign, nil
	}
	return 0, chunkMalformed()
}

// PartResult is the outcome of one part upload session.
type PartResult struct {
	// Count is the number of bytes the remote counted in the temporary file.
	Count int64
	// Stored is true only when Count equalled the expected length and the
	// part was renamed to its final name.
	Stored bool
}

// parsePartResult parses `SSJACK-PART <count> stored|short\n` for a part of
// the given length. `stored` is accepted only with count == length and
// `short` only with count != length.
func parsePartResult(data []byte, length int64) (PartResult, error) {
	line, ok := oneLine(data)
	if !ok {
		return PartResult{}, chunkMalformed()
	}
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "SSJACK-PART" {
		return PartResult{}, chunkMalformed()
	}
	count, ok := parseCanonical(fields[1])
	if !ok {
		return PartResult{}, chunkMalformed()
	}
	switch {
	case fields[2] == "stored" && count == length:
		return PartResult{Count: count, Stored: true}, nil
	case fields[2] == "short" && count != length:
		return PartResult{Count: count}, nil
	}
	return PartResult{}, chunkMalformed()
}

// StagingListing is the caller-side coverage built from a staging listing.
type StagingListing struct {
	// Parts are the accepted parts: ascending by offset, pairwise disjoint,
	// each exactly as long as its name says and inside the file.
	Parts []transferlink.Range
	// Remove names the listed entries that were ignored (overlapping,
	// wrong-size, past the end of the file or not a strict part name) and
	// should be removed with RemoveStagingEntries.
	Remove []string
	// Overflow reports more entries than the bound: the staging is corrupt
	// and should be removed. Parts and Remove are then empty.
	Overflow bool
	// StaleAssembled is the number of leftover assembled.<rnd>.tmp files the
	// listing session found and removed (a killed assembly can leave one behind,
	// as large as the whole file). They are gone before the listing returns, so
	// a disk-space decision made after it needs no allowance for them.
	StaleAssembled int
}

// staleLinePrefix starts the optional line `SSJACK-STALE <n>` that follows the
// listing header.
const staleLinePrefix = "SSJACK-STALE "

// maxListedPartsCap clamps the entry bound for very large byte limits (256
// GiB of 256 KiB parts), keeping the listing memory bounded.
const maxListedPartsCap = 1 << 20

// MaxListedParts is the bound on staging entries for a file limit: one part
// per 256 KiB (the smallest chunk) plus a small margin.
func MaxListedParts(l transfercore.Limits) int {
	const slice = 256 << 10
	n := l.MaxBytes / slice
	if l.MaxBytes%slice != 0 {
		n++
	}
	if n > maxListedPartsCap {
		n = maxListedPartsCap
	}
	return int(n) + 64
}

// listingBytesBound bounds the stdout of a listing session.
func listingBytesBound(maxParts int) int64 {
	return int64(maxParts+2)*96 + 256
}

// parseStagingListing strictly parses the listing output and builds the
// coverage. Only names shaped `part-` plus digits and dashes can appear in
// the output; strict names are then parsed with transferlink, entries are
// ordered by offset and, at one offset, longer first, and an entry that
// overlaps an accepted one, whose size differs from its length or that ends
// past fileSize is listed in Remove instead of Parts.
func parseStagingListing(data []byte, fileSize int64, maxParts int) (StagingListing, error) {
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		return StagingListing{}, chunkMalformed()
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) < 2 || lines[0] != "SSJACK-LIST 1" {
		return StagingListing{}, chunkMalformed()
	}
	last := lines[len(lines)-1]
	entries := lines[1 : len(lines)-1]
	stale := 0
	if len(entries) > 0 {
		if text, isStale := strings.CutPrefix(entries[0], staleLinePrefix); isStale {
			n, good := parseCanonical(text)
			if !good || n > maxListedPartsCap {
				return StagingListing{}, chunkMalformed()
			}
			stale = int(n)
			entries = entries[1:]
		}
	}
	if last == "SSJACK-OVERFLOW" {
		return StagingListing{Overflow: true, StaleAssembled: stale}, nil
	}
	count, ok := strings.CutPrefix(last, "SSJACK-END ")
	if n, good := parseCanonical(count); !ok || !good || n != int64(len(entries)) {
		return StagingListing{}, chunkMalformed()
	}
	if len(entries) > maxParts {
		return StagingListing{Overflow: true, StaleAssembled: stale}, nil
	}
	if fileSize < 0 {
		fileSize = 0
	}
	seen := make(map[string]struct{}, len(entries))
	var candidates []transferlink.Listed
	var remove []string
	for _, line := range entries {
		sizeText, name, ok := strings.Cut(line, " ")
		if !ok {
			return StagingListing{}, chunkMalformed()
		}
		size, ok := parseCanonical(sizeText)
		if !ok || !safePartName(name) {
			return StagingListing{}, chunkMalformed()
		}
		if _, dup := seen[name]; dup {
			return StagingListing{}, core.ListingError(transfercore.ClassIntegrity, msgChunkDuplicate)
		}
		seen[name] = struct{}{}
		rng, err := transferlink.ParsePartName(name)
		if err != nil {
			remove = append(remove, name)
			continue
		}
		candidates = append(candidates, transferlink.Listed{Name: name, Range: rng, Size: size})
	}
	accepted, rejected := transferlink.AcceptListed(fileSize, candidates)
	return StagingListing{Parts: accepted, Remove: append(remove, rejected...), StaleAssembled: stale}, nil
}

// safePartName mirrors the remote safe_name check: `part-` followed by one to
// 45 digits and dashes.
func safePartName(name string) bool {
	rest, ok := strings.CutPrefix(name, "part-")
	if !ok || rest == "" || len(rest) > 45 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if (rest[i] < '0' || rest[i] > '9') && rest[i] != '-' {
			return false
		}
	}
	return true
}

// parseGCResult parses `SSJACK-GC <n>\n` with n at most 16.
func parseGCResult(data []byte) (int, error) {
	line, ok := oneLine(data)
	if !ok {
		return 0, chunkMalformed()
	}
	count, ok := strings.CutPrefix(line, "SSJACK-GC ")
	if !ok {
		return 0, chunkMalformed()
	}
	n, ok := parseCanonical(count)
	if !ok || n > 16 {
		return 0, chunkMalformed()
	}
	return int(n), nil
}

// dfLine matches the data row of POSIX `df -P -k`: filesystem, total, used,
// available, capacity (`NN%` or `-`) and the mount point.
var dfLine = regexp.MustCompile(`^(\S.*?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(?:\d{1,3}%|-)\s+(\S.*)$`)

// parseDF extracts the available bytes from `df -P -k` output: a header line
// starting with `Filesystem` and exactly one data row. Anything else, an
// empty output or numbers that do not fit means "skip the check" (ok false).
func parseDF(data []byte) (avail int64, ok bool) {
	s := strings.TrimSuffix(string(data), "\n")
	lines := strings.Split(s, "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "Filesystem") {
		return 0, false
	}
	m := dfLine.FindStringSubmatch(lines[1])
	if m == nil {
		return 0, false
	}
	kib, err := strconv.ParseInt(m[4], 10, 64)
	if err != nil || kib < 0 {
		return 0, false
	}
	if kib > math.MaxInt64/1024 {
		return math.MaxInt64, true
	}
	return kib * 1024, true
}

// SourceStat is the size and whole-second modification time of a remote file.
type SourceStat struct {
	Size  int64
	MTime int64
}

// parseSourceStat parses `<size> <mtime>\n`, both canonical decimals.
func parseSourceStat(data []byte) (SourceStat, error) {
	line, ok := oneLine(data)
	if !ok {
		return SourceStat{}, chunkMalformed()
	}
	sizeText, mtimeText, ok := strings.Cut(line, " ")
	if !ok {
		return SourceStat{}, chunkMalformed()
	}
	size, ok := parseCanonical(sizeText)
	if !ok {
		return SourceStat{}, chunkMalformed()
	}
	mtime, ok := parseCanonical(mtimeText)
	if !ok {
		return SourceStat{}, chunkMalformed()
	}
	return SourceStat{Size: size, MTime: mtime}, nil
}
