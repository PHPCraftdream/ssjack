package discovery

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
)

// DescriptorHash re-derives the descriptor fingerprint (lowercase hex of
// SHA-256 over canonical JSON, the same value the scanner reports as
// Candidate.Fingerprint / hex-encoded in approval records) for the keeper to
// re-verify an approval (OWNER-VAULT-SNAPSHOT 4.2.1). The input must be the
// approval record's canonical application path, exactly as stored in
// Candidate.CanonicalPath. A path that has since been replaced by a
// symlink/junction or rebound is refused with "path_not_canonical", because
// the approval binds the hash to that canonical path and folder identity; a
// swap during the descriptor read is refused with "root_changed". It reuses
// the scanner's exact bounded no-link read-and-fingerprint path and returns an
// error with a log-safe reason code (no descriptor content, no OS error
// strings) whenever the scanner would reject the directory or its descriptor;
// a missing descriptor is an error too.
func DescriptorHash(directory string) (string, error) {
	root, rootDir, rootPath, rootInfo, reason := openRootGuarded(directory)
	if reason != "" {
		if rootDir != nil {
			_ = rootDir.Close()
		}
		if root != nil {
			_ = root.Close()
		}
		return "", errors.New(reason)
	}
	defer root.Close()
	defer rootDir.Close()

	if !samePath(rootPath, filepath.Clean(directory)) {
		return "", errors.New("path_not_canonical")
	}
	_, _, digest, reason := readValidatedDescriptor(root)
	if reason != "" {
		return "", errors.New(reason)
	}
	if !rootPathStillMatches(rootPath, rootInfo) {
		return "", errors.New("root_changed")
	}
	return hex.EncodeToString(digest[:]), nil
}

// samePath compares the resolved root with the stored canonical path; a link anywhere in the input (final component or ancestor) makes them differ. Windows paths are case-insensitive.
func samePath(resolved, stored string) bool {
	return resolved == stored || (runtime.GOOS == "windows" && strings.EqualFold(resolved, stored))
}
