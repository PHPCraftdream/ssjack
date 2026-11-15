package transferlocal

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Root is one owner-registered transfer root directory.
type Root struct {
	name string
	path string // cleaned absolute path; never included in any error message
}

// Name returns the root name, "" for an unnamed root.
func (r *Root) Name() string {
	if r == nil {
		return ""
	}
	return r.name
}

// Dir returns the absolute root path for in-process use only; it is never
// shown to the model.
func (r *Root) Dir() string {
	if r == nil {
		return ""
	}
	return r.path
}

func refusedPath(message string) error {
	return transfercore.Fail(transfercore.ClassRefusedPath, message)
}

// ParseRoot parses "[NAME=]DIR" and verifies the directory as a transfer root.
func ParseRoot(spec string, vaultPath string) (*Root, error) {
	name, dir, hasName := strings.Cut(spec, "=")
	if !hasName {
		dir = spec
		name = ""
	}
	if name != "" {
		if err := validRootName(name); err != nil {
			return nil, err
		}
	} else if hasName {
		return nil, refusedPath("transfer root name is invalid")
	}
	if !filepath.IsAbs(dir) {
		return nil, refusedPath("transfer root must be an absolute path")
	}
	path := filepath.Clean(dir)
	if err := verifyRealDirTree(path); err != nil {
		return nil, err
	}
	if isFilesystemRoot(path) {
		return nil, refusedPath("transfer root must not be a filesystem root")
	}
	if vaultPath != "" {
		if err := checkVaultOutside(path, vaultPath); err != nil {
			return nil, err
		}
	}
	return &Root{name: name, path: path}, nil
}

// validRootName accepts 1..64 bytes of [A-Za-z0-9._-].
func validRootName(name string) error {
	if len(name) < 1 || len(name) > 64 {
		return refusedPath("transfer root name is invalid")
	}
	for _, r := range name {
		ok := r == '.' || r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return refusedPath("transfer root name is invalid")
		}
	}
	return nil
}

// checkVaultOutside refuses a vault path inside the root (or equal to it).
func checkVaultOutside(root, vault string) error {
	if !filepath.IsAbs(vault) {
		return refusedPath("vault path must be absolute")
	}
	vault = filepath.Clean(vault)
	if vault == root || strings.HasPrefix(vault, root+string(os.PathSeparator)) {
		return refusedPath("transfer root must not contain the vault")
	}
	return nil
}

// Roots is a collection of registered roots; the zero value is usable but
// NewRoots is preferred.
type Roots struct {
	mu     sync.Mutex
	byName map[string]*Root
}

// NewRoots returns an empty root collection.
func NewRoots() *Roots {
	return &Roots{byName: make(map[string]*Root)}
}

// Add registers a root, refusing nil roots and duplicate names.
func (rs *Roots) Add(root *Root) error {
	if root == nil {
		return refusedPath("transfer root is missing")
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.byName == nil {
		rs.byName = make(map[string]*Root)
	}
	if _, ok := rs.byName[root.name]; ok {
		return refusedPath("duplicate transfer root name")
	}
	rs.byName[root.name] = root
	return nil
}

// Select returns the requested root; "" selects the only registered root.
func (rs *Roots) Select(name string) (*Root, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if len(rs.byName) == 0 {
		return nil, refusedPath("no transfer roots are registered")
	}
	if name == "" {
		if len(rs.byName) != 1 {
			return nil, refusedPath("a transfer root name is required when several roots are registered")
		}
		for _, root := range rs.byName {
			return root, nil
		}
	}
	root, ok := rs.byName[name]
	if !ok {
		return nil, refusedPath("transfer root was not registered")
	}
	return root, nil
}
