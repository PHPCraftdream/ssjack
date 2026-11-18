package pathsafe

import (
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/osfs"
)

// VerifyRealDirTree walks every ancestor prefix of an absolute cleaned path
// with osfs.StatPath and refuses anything missing, non-directory, a symlink or
// reparse point, or a filesystem root. It is the boundary for ParseRoot and
// for NewStaging parent checks.
func VerifyRealDirTree(abs string) error {
	if !filepath.IsAbs(abs) {
		return Refused("path is not absolute")
	}
	clean := filepath.Clean(abs)
	if IsFilesystemRoot(clean) {
		return Refused("path must not be a filesystem root")
	}
	for current := clean; len(current) > len(filepath.VolumeName(current))+1; current = filepath.Dir(current) {
		info, err := osfs.StatPath(current)
		if err != nil {
			return Refused("path cannot be inspected")
		}
		if !info.Exist {
			return Refused("path does not exist")
		}
		if info.Reparse {
			return Refused("path contains a symlink or reparse point")
		}
		if !info.Dir {
			return Refused("path is not a directory")
		}
	}
	return nil
}

// IsFilesystemRoot reports whether a cleaned absolute path is a filesystem
// root: "/" on unix, a volume root like C:\ or a UNC share root on windows.
func IsFilesystemRoot(abs string) bool {
	clean := filepath.Clean(abs)
	if clean == "/" {
		return true
	}
	volume := filepath.VolumeName(clean)
	if volume == "" {
		return false
	}
	// A share root is its own volume name; a drive root ends at the separator.
	return clean == volume || clean == volume+string(filepath.Separator)
}

// ResolveStructural validates rel and walks component by component under the
// root without following symlinks or reparse points at any component.
func ResolveStructural(root, rel string, limits transfercore.Limits) (string, osfs.PathInfo, error) {
	if rel == "" {
		if err := VerifyRealDirTree(root); err != nil {
			return "", osfs.PathInfo{}, err
		}
		info, err := osfs.StatPath(root)
		if err != nil {
			return "", osfs.PathInfo{}, Refused("path cannot be inspected")
		}
		if !info.Exist || !info.Dir {
			return "", osfs.PathInfo{}, Refused("path is not a directory")
		}
		return root, info, nil
	}
	if err := ValidateLocalRelPath(rel, limits); err != nil {
		return "", osfs.PathInfo{}, err
	}
	parts := strings.Split(rel, "/")
	abs := root
	var last osfs.PathInfo
	for i, part := range parts {
		abs = filepath.Join(abs, part)
		info, err := osfs.StatPath(abs)
		if err != nil {
			return "", osfs.PathInfo{}, Refused("path cannot be inspected")
		}
		if !info.Exist {
			return "", osfs.PathInfo{}, Refused("path does not exist under the root")
		}
		if info.Reparse {
			return "", osfs.PathInfo{}, Refused("path contains a symlink or reparse point")
		}
		if i < len(parts)-1 && !info.Dir {
			return "", osfs.PathInfo{}, Refused("path component is not a directory")
		}
		last = info
	}
	return abs, last, nil
}

// resolveDir is ResolveStructural plus: the final component must be a
// directory.
func resolveDir(root, rel string, limits transfercore.Limits) (string, error) {
	abs, info, err := ResolveStructural(root, rel, limits)
	if err != nil {
		return "", err
	}
	if !info.Dir {
		return "", Refused("path is not a directory")
	}
	return abs, nil
}

// resolveDestination validates a destination rel path and returns its parent
// directory and final component. The final component may already exist; the
// overwrite decision belongs to the caller.
func resolveDestination(root, rel string, limits transfercore.Limits) (dir string, name string, err error) {
	if rel == "" {
		return "", "", Refused("destination path is empty")
	}
	if ForbiddenRelPath(rel) {
		return "", "", Refused("destination contains a forbidden control directory")
	}
	parentRel, base := SplitRelName(rel)
	if parentRel != "" {
		if _, err := resolveDir(root, parentRel, limits); err != nil {
			return "", "", err
		}
	} else if err := VerifyRealDirTree(root); err != nil {
		return "", "", err
	}
	abs, info, err := ResolveStructural(root, rel, limits)
	if err != nil {
		return "", "", err
	}
	if info.Reparse {
		return "", "", Refused("destination is a symlink or reparse point")
	}
	return filepath.Dir(abs), base, nil
}
