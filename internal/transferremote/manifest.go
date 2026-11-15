package transferremote

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Fixed, content-free manifest error messages.
const (
	msgManifestMalformed = "manifest stream could not be parsed"
	msgManifestDuplicate = "manifest contains a duplicate entry"
	msgManifestInvalid   = "manifest contains an invalid entry"
)

// FormatManifest serializes a canonical manifest stream: sorted lines of
// `d <dir>\n` and `f <size> <hex> <path>\n`. The path is everything after
// the third space; paths may contain spaces but never newlines or
// backslashes. The caller's slices are not mutated.
func FormatManifest(m transfercore.Manifest, l transfercore.Limits) ([]byte, error) {
	c := transfercore.Manifest{
		Dirs:  append([]string(nil), m.Dirs...),
		Files: append([]transfercore.Entry(nil), m.Files...),
	}
	c.Normalize()
	dirSeen := make(map[string]struct{}, len(c.Dirs))
	for _, dir := range c.Dirs {
		if err := refuseRelPath(dir, l); err != nil {
			return nil, err
		}
		if _, ok := dirSeen[dir]; ok {
			return nil, transfercore.Fail(transfercore.ClassIntegrity, msgManifestDuplicate)
		}
		dirSeen[dir] = struct{}{}
	}
	fileSeen := make(map[string]struct{}, len(c.Files))
	for _, file := range c.Files {
		if err := refuseRelPath(file.Path, l); err != nil {
			return nil, err
		}
		if file.Size < 0 {
			return nil, transfercore.Fail(transfercore.ClassIntegrity, msgManifestInvalid)
		}
		if _, ok := fileSeen[file.Path]; ok {
			return nil, transfercore.Fail(transfercore.ClassIntegrity, msgManifestDuplicate)
		}
		fileSeen[file.Path] = struct{}{}
	}
	var b strings.Builder
	for _, dir := range c.Dirs {
		b.WriteString("d ")
		b.WriteString(dir)
		b.WriteString("\n")
	}
	for _, file := range c.Files {
		b.WriteString("f ")
		b.WriteString(strconv.FormatInt(file.Size, 10))
		b.WriteString(" ")
		b.WriteString(hex.EncodeToString(file.SHA256[:]))
		b.WriteString(" ")
		b.WriteString(file.Path)
		b.WriteString("\n")
	}
	return []byte(b.String()), nil
}

// ParseManifest parses a canonical manifest stream as written by
// FormatManifest. Local parse failures carry ClassIntegrity with no remote
// exit code.
func ParseManifest(data []byte, l transfercore.Limits) (transfercore.Manifest, error) {
	if len(data) == 0 {
		return transfercore.Manifest{}, nil
	}
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, msgManifestMalformed)
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	dirs := make([]string, 0, len(lines))
	files := make([]transfercore.Entry, 0, len(lines))
	dirSeen := make(map[string]struct{}, len(lines))
	fileSeen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "d "):
			dir := line[2:]
			if dir == "" {
				return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, msgManifestMalformed)
			}
			if err := refuseRelPath(dir, l); err != nil {
				return transfercore.Manifest{}, err
			}
			if _, ok := dirSeen[dir]; ok {
				return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, msgManifestDuplicate)
			}
			dirSeen[dir] = struct{}{}
			dirs = append(dirs, dir)
		case strings.HasPrefix(line, "f "):
			rest := line[2:]
			parts := strings.SplitN(rest, " ", 3)
			if len(parts) != 3 {
				return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, msgManifestMalformed)
			}
			size, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil || size < 0 {
				return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, msgManifestMalformed)
			}
			raw, err := hex.DecodeString(parts[1])
			if err != nil || len(raw) != 32 {
				return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, msgManifestMalformed)
			}
			var hash [32]byte
			copy(hash[:], raw)
			path := parts[2]
			if path == "" {
				return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, msgManifestMalformed)
			}
			if err := refuseRelPath(path, l); err != nil {
				return transfercore.Manifest{}, err
			}
			if _, ok := fileSeen[path]; ok {
				return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, msgManifestDuplicate)
			}
			fileSeen[path] = struct{}{}
			files = append(files, transfercore.Entry{Path: path, Size: size, SHA256: hash})
		default:
			return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, msgManifestMalformed)
		}
	}
	if len(dirs)+len(files) > l.MaxEntries {
		return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassLimit, msgTreeLimit)
	}
	m := transfercore.Manifest{Dirs: dirs, Files: files}
	if err := m.CheckLimits(l); err != nil {
		return transfercore.Manifest{}, err
	}
	return m, nil
}
