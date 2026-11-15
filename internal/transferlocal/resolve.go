package transferlocal

import (
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// verifyRealDirTree walks every ancestor prefix of an absolute cleaned path
// with statPath and refuses anything missing, non-directory, a symlink or
// reparse point, or a filesystem root. It is the boundary for ParseRoot and
// for NewStaging parent checks.
func verifyRealDirTree(abs string) error {
	if !filepath.IsAbs(abs) {
		return refusedPath("path is not absolute")
	}
	clean := filepath.Clean(abs)
	if isFilesystemRoot(clean) {
		return refusedPath("path must not be a filesystem root")
	}
	for current := clean; len(current) > len(filepath.VolumeName(current))+1; current = filepath.Dir(current) {
		info, err := statPath(current)
		if err != nil {
			return refusedPath("path cannot be inspected")
		}
		if !info.exist {
			return refusedPath("path does not exist")
		}
		if info.reparse {
			return refusedPath("path contains a symlink or reparse point")
		}
		if !info.dir {
			return refusedPath("path is not a directory")
		}
	}
	return nil
}

// isFilesystemRoot reports whether a cleaned absolute path is a filesystem
// root: "/" on unix, a volume root like C:\ or a UNC share root on windows.
func isFilesystemRoot(abs string) bool {
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

// resolveStructural validates rel and walks component by component under the
// root without following symlinks or reparse points at any component.
func (r *Root) resolveStructural(rel string, limits transfercore.Limits) (string, pathInfo, error) {
	if rel == "" {
		if err := verifyRealDirTree(r.path); err != nil {
			return "", pathInfo{}, err
		}
		info, err := statPath(r.path)
		if err != nil {
			return "", pathInfo{}, refusedPath("path cannot be inspected")
		}
		if !info.exist || !info.dir {
			return "", pathInfo{}, refusedPath("path is not a directory")
		}
		return r.path, info, nil
	}
	if err := validateLocalRelPath(rel, limits); err != nil {
		return "", pathInfo{}, err
	}
	parts := strings.Split(rel, "/")
	abs := r.path
	var last pathInfo
	for i, part := range parts {
		abs = filepath.Join(abs, part)
		info, err := statPath(abs)
		if err != nil {
			return "", pathInfo{}, refusedPath("path cannot be inspected")
		}
		if !info.exist {
			return "", pathInfo{}, refusedPath("path does not exist under the root")
		}
		if info.reparse {
			return "", pathInfo{}, refusedPath("path contains a symlink or reparse point")
		}
		if i < len(parts)-1 && !info.dir {
			return "", pathInfo{}, refusedPath("path component is not a directory")
		}
		last = info
	}
	return abs, last, nil
}

// resolveDir is resolveStructural plus: the final component must be a
// directory.
func (r *Root) resolveDir(rel string, limits transfercore.Limits) (string, error) {
	abs, info, err := r.resolveStructural(rel, limits)
	if err != nil {
		return "", err
	}
	if !info.dir {
		return "", refusedPath("path is not a directory")
	}
	return abs, nil
}

// resolveDestination validates a destination rel path and returns its parent
// directory and final component. The final component may already exist; the
// overwrite decision belongs to the caller.
func (r *Root) resolveDestination(rel string, limits transfercore.Limits) (dir string, name string, err error) {
	if rel == "" {
		return "", "", refusedPath("destination path is empty")
	}
	if forbiddenRelPath(rel) {
		return "", "", refusedPath("destination contains a forbidden control directory")
	}
	parentRel, base := splitRelName(rel)
	if parentRel != "" {
		if _, err := r.resolveDir(parentRel, limits); err != nil {
			return "", "", err
		}
	} else if err := verifyRealDirTree(r.path); err != nil {
		return "", "", err
	}
	abs, info, err := r.resolveStructural(rel, limits)
	if err != nil {
		return "", "", err
	}
	if info.reparse {
		return "", "", refusedPath("destination is a symlink or reparse point")
	}
	return filepath.Dir(abs), base, nil
}
