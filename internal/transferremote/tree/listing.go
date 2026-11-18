package tree

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

// Fixed, content-free listing error messages.
const (
	msgTreeLimit        = "remote tree exceeds the configured limits"
	msgListingMalformed = "remote listing could not be parsed"
	msgListingDuplicate = "remote listing contains a duplicate entry"
	msgSizeMissing      = "remote size listing is missing an entry"
	msgSizeUnknown      = "remote size listing has an unknown entry"
	msgNameBackslash    = "remote file names may not contain a backslash"
)

// listingBound bounds the bytes a listing command may write so a hostile
// host cannot flood memory: each entry can be at most one path plus slack.
func listingBound(l transfercore.Limits) int64 {
	return int64(l.MaxEntries)*(int64(l.MaxPathBytes)+80) + 4096
}

// refuseRelPath validates a root-relative path with transfercore and refuses
// backslash names, which would be ambiguous in escaped listings.
func refuseRelPath(rel string, l transfercore.Limits) error {
	if err := transfercore.ValidateRelPath(rel, l); err != nil {
		return err
	}
	if strings.ContainsRune(rel, '\\') {
		return transfercore.Fail(transfercore.ClassRefusedPath, msgNameBackslash)
	}
	return nil
}

// parseDirListing parses NUL-separated directory paths from
// `find root -type d -print0`. The root itself is skipped. bad is the class
// for structural problems (refused_path in preflight, integrity in
// verification). An empty stream yields no directories.
func parseDirListing(data []byte, root string, l transfercore.Limits, bad transfercore.Class) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}
	s := string(data)
	if !strings.HasSuffix(s, "\x00") {
		return nil, core.ListingError(bad, msgListingMalformed)
	}
	items := strings.Split(strings.TrimSuffix(s, "\x00"), "\x00")
	dirs := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item == root {
			continue
		}
		if !strings.HasPrefix(item, root+"/") {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		rel := item[len(root)+1:]
		if err := refuseRelPath(rel, l); err != nil {
			return nil, err
		}
		if _, ok := seen[rel]; ok {
			return nil, core.ListingError(bad, msgListingDuplicate)
		}
		seen[rel] = struct{}{}
		dirs = append(dirs, rel)
	}
	if len(dirs) > l.MaxEntries {
		return nil, core.ListingError(transfercore.ClassLimit, msgTreeLimit)
	}
	return dirs, nil
}

// parseFileListing parses lines of sha256sum output: `<64 hex>  <path>\n`.
// A line starting with a backslash is a GNU escape for a name containing a
// newline or backslash; such names are refused, so it is malformed here. A
// line naming "-" is skipped: with empty input xargs -0 still runs
// sha256sum once, and sha256sum then reads stdin and labels it "-"; no real
// path can be exactly "-" because find prints absolute paths.
func parseFileListing(data []byte, root string, l transfercore.Limits, bad transfercore.Class) ([]transfercore.Entry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		return nil, core.ListingError(bad, msgListingMalformed)
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	entries := make([]transfercore.Entry, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		if line == "" {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		if strings.HasPrefix(line, "\\") {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		if len(line) < 67 {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		raw, err := hex.DecodeString(line[0:64])
		if err != nil {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		var hash [32]byte
		copy(hash[:], raw)
		if line[64:66] != "  " {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		name := line[66:]
		if name == "-" {
			continue
		}
		if !strings.HasPrefix(name, root+"/") {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		rel := name[len(root)+1:]
		if err := refuseRelPath(rel, l); err != nil {
			return nil, err
		}
		if _, ok := seen[rel]; ok {
			return nil, core.ListingError(bad, msgListingDuplicate)
		}
		seen[rel] = struct{}{}
		entries = append(entries, transfercore.Entry{Path: rel, SHA256: hash})
	}
	if len(entries) > l.MaxEntries {
		return nil, core.ListingError(transfercore.ClassLimit, msgTreeLimit)
	}
	return entries, nil
}

// parseSizeListing parses lines of `wc -c` output from
// `xargs -0 -n 1 wc -c`: one file per invocation, so exactly one space
// separates the count from the name, with possible leading padding spaces.
// A line that is only a number (no name) is skipped: wc with no operand
// reads stdin and prints a bare count, so it is a phantom, not an entry.
func parseSizeListing(data []byte, root string, l transfercore.Limits, bad transfercore.Class) (map[string]int64, error) {
	sizes := map[string]int64{}
	if len(data) == 0 {
		return sizes, nil
	}
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		return nil, core.ListingError(bad, msgListingMalformed)
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		if line == "" {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		i := 0
		for i < len(line) && line[i] == ' ' {
			i++
		}
		j := i
		for j < len(line) && line[j] >= '0' && line[j] <= '9' {
			j++
		}
		if j == i {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		if j == len(line) {
			continue
		}
		if line[j] != ' ' {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		size, err := strconv.ParseInt(line[i:j], 10, 64)
		if err != nil || size < 0 {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		name := line[j+1:]
		if name == "" {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		if !strings.HasPrefix(name, root+"/") {
			return nil, core.ListingError(bad, msgListingMalformed)
		}
		rel := name[len(root)+1:]
		if err := refuseRelPath(rel, l); err != nil {
			return nil, err
		}
		if _, ok := seen[rel]; ok {
			return nil, core.ListingError(bad, msgListingDuplicate)
		}
		seen[rel] = struct{}{}
		sizes[rel] = size
	}
	if len(sizes) > l.MaxEntries {
		return nil, core.ListingError(transfercore.ClassLimit, msgTreeLimit)
	}
	return sizes, nil
}
