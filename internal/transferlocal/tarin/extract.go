// Package tarin extracts a tar stream into a staging directory under the
// local safety rules.
package tarin

import (
	"archive/tar"
	"io"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/osfs"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/pathsafe"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/staging"
)

// ExtractTar reads a tar stream into the staging directory, enforcing every
// local safety rule while streaming, hashing while extracting, and returns
// the normalized computed manifest. The "./"-rooted layout of
// `tar -c -f - .` is accepted: the root entry "./"/"." is skipped and exactly
// one leading "./" is stripped before validation. Hard-link entries remain
// refused by the type filter. When want is non-nil it must match
// exactly or the failure is an integrity error.
func ExtractTar(r io.Reader, stg *staging.Staging, want *transfercore.Manifest, limits transfercore.Limits) (transfercore.Manifest, error) {
	if stg == nil {
		return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassInternal, "staging is missing")
	}
	if err := limits.Validate(); err != nil {
		return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassInternal, "transfer limits are invalid")
	}
	if err := stg.Writable(); err != nil {
		return transfercore.Manifest{}, err
	}
	root := stg.Path()
	tr := tar.NewReader(r)
	seen := make(map[string]struct{})
	folded := make(map[string]struct{})
	dirsSet := make(map[string]struct{})
	var computed transfercore.Manifest
	var dirTimes []dirTime
	entries := 0
	var totalBytes int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, "archive is truncated or malformed")
		}
		entries++
		if entries > limits.MaxEntries {
			return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassLimit, "transfer exceeds the configured limits")
		}
		var isDir bool
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
		case tar.TypeDir:
			isDir = true
		default:
			return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassRefusedPath, "archive contains an unsupported entry type")
		}
		name := hdr.Name
		if isDir && strings.HasSuffix(name, "/") {
			name = strings.TrimSuffix(name, "/")
		}
		if name == "." {
			if isDir {
				// The archive root of `tar -c -f - .`.
				continue
			}
			return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, "archive entry name is malformed")
		}
		if strings.HasPrefix(name, "./") {
			name = strings.TrimPrefix(name, "./")
		}
		if name == "" {
			return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassRefusedPath, "archive entry has an empty name")
		}
		if !isDir && strings.HasSuffix(name, "/") {
			return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, "archive entry name is malformed")
		}
		if err := pathsafe.ValidateLocalRelPath(name, limits); err != nil {
			return transfercore.Manifest{}, err
		}
		if pathsafe.ForbiddenRelPath(name) {
			return transfercore.Manifest{}, pathsafe.Refused("archive entry contains a forbidden control directory")
		}
		if _, dup := seen[name]; dup {
			return transfercore.Manifest{}, pathsafe.Refused("archive contains a duplicate entry name")
		}
		if _, dup := folded[pathsafe.FoldKey(name)]; dup {
			return transfercore.Manifest{}, pathsafe.Refused("archive contains a case-insensitive duplicate entry name")
		}
		seen[name] = struct{}{}
		folded[pathsafe.FoldKey(name)] = struct{}{}
		if hdr.Size < 0 {
			return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, "archive entry size is invalid")
		}
		if isDir {
			created, err := ensureDirChain(root, name)
			if err != nil {
				return transfercore.Manifest{}, err
			}
			recordDirs(&computed, dirsSet, created)
			recordDirs(&computed, dirsSet, []string{name})
			dirTimes = append(dirTimes, dirTime{rel: name, modTime: hdr.ModTime})
			continue
		}
		parentDir, _ := pathsafe.SplitRelName(name)
		created, err := ensureDirChain(root, parentDir)
		if err != nil {
			return transfercore.Manifest{}, err
		}
		recordDirs(&computed, dirsSet, created)
		n, digest, err := extractFileEntry(root, name, tr, hdr.Size, hdr.Mode&0100 != 0, hdr.ModTime, &totalBytes, limits)
		if err != nil {
			return transfercore.Manifest{}, err
		}
		computed.Files = append(computed.Files, transfercore.Entry{Path: name, Size: n, SHA256: digest})
	}
	applyDirTimes(root, dirTimes)
	// Publish re-checks the staging state; a failed directory sync is
	// best-effort here.
	_ = osfs.SyncDirectory(root)
	computed.Normalize()
	if want != nil && !manifestsEqual(computed, *want) {
		return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassIntegrity, "archive does not match the expected manifest")
	}
	return computed, nil
}

// recordDirs appends created rel directories once, in order.
func recordDirs(m *transfercore.Manifest, dirsSet map[string]struct{}, created []string) {
	for _, d := range created {
		if _, ok := dirsSet[d]; ok {
			continue
		}
		dirsSet[d] = struct{}{}
		m.Dirs = append(m.Dirs, d)
	}
}

// manifestsEqual compares two normalized manifests exactly.
func manifestsEqual(a, b transfercore.Manifest) bool {
	if len(a.Dirs) != len(b.Dirs) || len(a.Files) != len(b.Files) {
		return false
	}
	for i := range a.Dirs {
		if a.Dirs[i] != b.Dirs[i] {
			return false
		}
	}
	for i := range a.Files {
		if a.Files[i].Path != b.Files[i].Path || a.Files[i].Size != b.Files[i].Size || a.Files[i].SHA256 != b.Files[i].SHA256 {
			return false
		}
	}
	return true
}

// joinOSPath joins an absolute root with a slash-separated rel path.
func joinOSPath(root, rel string) string {
	return filepath.Join(root, filepath.FromSlash(rel))
}
