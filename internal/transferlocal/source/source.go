// Package source reads local files and trees for sending: manifest walk,
// no-follow open and deterministic tar output under the local safety rules.
package source

import (
	"io"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/hashcount"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/osfs"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/pathsafe"
)

// walkState carries the walk budget so a tree can be refused while walking,
// not only after the manifest is complete.
type walkState struct {
	limits transfercore.Limits
	total  int64
	count  int
}

// Walk walks the tree at rel under the root and returns the manifest of
// regular files and directories only. rel "" means the root itself; a regular
// file rel yields a single-file manifest. Tree manifests list dirs and files
// relative to the walked rel directory; walking a single regular file yields
// a one-entry manifest whose Path is rel itself.
func Walk(root, rel string, limits transfercore.Limits) (transfercore.Manifest, error) {
	if err := limits.Validate(); err != nil {
		return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassInternal, "transfer limits are invalid")
	}
	abs, info, err := pathsafe.ResolveStructural(root, rel, limits)
	if err != nil {
		return transfercore.Manifest{}, err
	}
	var m transfercore.Manifest
	if info.Regular && rel != "" {
		if info.MultiLinked {
			return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassRefusedPath, "source file has more than one hard link")
		}
		n, digest, err := hashOneFile(abs, &walkState{limits: limits})
		if err != nil {
			return transfercore.Manifest{}, err
		}
		m.Files = append(m.Files, transfercore.Entry{Path: rel, Size: n, SHA256: digest})
		m.Normalize()
		return m, nil
	}
	if !info.Dir {
		return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassRefusedPath, "source entry type is not supported")
	}
	state := &walkState{limits: limits}
	if err := walk(abs, "", &m, state); err != nil {
		return transfercore.Manifest{}, err
	}
	m.Normalize()
	return m, nil
}

// walk recurses one directory, refusing anything that is not a plain file or
// directory and re-checking limits on every entry.
func walk(absDir, relPrefix string, m *transfercore.Manifest, state *walkState) error {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "source directory cannot be read")
	}
	for _, entry := range entries {
		childRel := pathsafe.JoinRel(relPrefix, entry.Name())
		if err := pathsafe.ValidateLocalRelPath(childRel, state.limits); err != nil {
			return err
		}
		absPath := filepath.Join(absDir, entry.Name())
		info, err := osfs.StatPath(absPath)
		if err != nil {
			return transfercore.Fail(transfercore.ClassIntegrity, "source changed during the walk")
		}
		if !info.Exist {
			return transfercore.Fail(transfercore.ClassIntegrity, "source changed during the walk")
		}
		if info.Reparse {
			return transfercore.Fail(transfercore.ClassRefusedPath, "source contains a symlink or reparse point")
		}
		switch {
		case info.Dir:
			state.count++
			if err := checkEntryLimit(state); err != nil {
				return err
			}
			m.Dirs = append(m.Dirs, childRel)
			if err := walk(absPath, childRel, m, state); err != nil {
				return err
			}
		case info.Regular:
			state.count++
			if err := checkEntryLimit(state); err != nil {
				return err
			}
			if info.MultiLinked {
				return transfercore.Fail(transfercore.ClassRefusedPath, "source file has more than one hard link")
			}
			n, digest, err := hashOneFile(absPath, state)
			if err != nil {
				return err
			}
			m.Files = append(m.Files, transfercore.Entry{Path: childRel, Size: n, SHA256: digest})
		default:
			return transfercore.Fail(transfercore.ClassRefusedPath, "source entry type is not supported")
		}
	}
	return nil
}

// checkEntryLimit enforces the entry-count budget as entries are discovered.
func checkEntryLimit(state *walkState) error {
	if state.count > state.limits.MaxEntries {
		return transfercore.Fail(transfercore.ClassLimit, "transfer exceeds the configured limits")
	}
	return nil
}

// hashOneFile hashes one source file, refusing a size change between stat and
// read and enforcing the byte budget before opening it.
func hashOneFile(absPath string, state *walkState) (int64, [32]byte, error) {
	info, err := osfs.StatPath(absPath)
	if err != nil || !info.Exist {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassIntegrity, "source changed during the walk")
	}
	if state.total+info.Size > state.limits.MaxBytes {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassLimit, "transfer exceeds the configured limits")
	}
	file, _, err := osfs.OpenRegularNoFollow(absPath)
	if err != nil {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassRefusedPath, "source file cannot be opened")
	}
	c := hashcount.New(nil)
	_, copyErr := io.Copy(c, file)
	_ = file.Close()
	if copyErr != nil {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassInternal, "source could not be read")
	}
	n := c.Count()
	if n != info.Size {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassIntegrity, "source changed during the walk")
	}
	state.total += n
	return n, c.Sum(), nil
}

// OpenFile no-follow opens rel as a regular file for single-file
// transfers. DefaultLimits is the maximum bound; the engine applies tighter
// configured limits earlier.
func OpenFile(root, rel string) (*os.File, int64, error) {
	limits := transfercore.DefaultLimits()
	abs, info, err := pathsafe.ResolveStructural(root, rel, limits)
	if err != nil {
		return nil, 0, err
	}
	if !info.Regular {
		return nil, 0, transfercore.Fail(transfercore.ClassRefusedPath, "source is not a regular file")
	}
	if info.MultiLinked {
		return nil, 0, transfercore.Fail(transfercore.ClassRefusedPath, "source file has more than one hard link")
	}
	file, size, err := osfs.OpenRegularNoFollow(abs)
	if err != nil {
		return nil, 0, transfercore.Fail(transfercore.ClassRefusedPath, "source file cannot be opened")
	}
	return file, size, nil
}
