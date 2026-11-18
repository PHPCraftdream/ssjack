package staging

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/osfs"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/pathsafe"
)

// removeTree removes a tree this package created; callers convert the raw
// error.
func removeTree(path string) error {
	return os.RemoveAll(path)
}

// renameFunc renames source to target; it is a seam so tests can force
// publication failures. Production always uses os.Rename.
var renameFunc = os.Rename

// publishFile publishes the staged single file at destAbs.
func (s *Staging) publishFile(destAbs string) error {
	payload := filepath.Join(s.path, PayloadName)
	info, err := osfs.StatPath(payload)
	if err != nil || !info.Exist {
		return transfercore.Fail(transfercore.ClassInternal, "staging payload is missing")
	}
	if !info.Regular || info.Reparse {
		return transfercore.Fail(transfercore.ClassInternal, "staging payload is not a regular file")
	}
	if err := osfs.SyncPathData(payload); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "staged data could not be flushed")
	}
	dinfo, err := osfs.StatPath(destAbs)
	if err != nil {
		return pathsafe.Refused("destination cannot be inspected")
	}
	if dinfo.Reparse {
		return pathsafe.Refused("destination is a symlink or reparse point")
	}
	if !s.overwrite {
		err := osfs.HardLinkNoClobber(payload, destAbs)
		switch {
		case err == nil:
			return nil
		case err == osfs.ErrDestinationExists:
			return transfercore.Fail(transfercore.ClassExists, "destination already exists")
		case err == osfs.ErrHardLinkUnsupported:
			// Existence-check-then-rename fallback is racy, per the spec.
			if dinfo.Exist {
				return transfercore.Fail(transfercore.ClassExists, "destination already exists")
			}
			if err := renameFunc(payload, destAbs); err != nil {
				return transfercore.Fail(transfercore.ClassInternal, "destination could not be published")
			}
			return nil
		default:
			return transfercore.Fail(transfercore.ClassInternal, "destination could not be published")
		}
	}
	if dinfo.Exist && dinfo.Dir {
		return pathsafe.Refused("destination is a directory")
	}
	if dinfo.Exist && !dinfo.Regular {
		return pathsafe.Refused("destination is not a regular file")
	}
	if err := osfs.RenameReplaceFile(payload, destAbs); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "destination could not be replaced")
	}
	return nil
}

// publishDir publishes the staged tree at destAbs by rename only.
func (s *Staging) publishDir(destAbs string) error {
	dinfo, err := osfs.StatPath(destAbs)
	if err != nil {
		return pathsafe.Refused("destination cannot be inspected")
	}
	if dinfo.Reparse {
		return pathsafe.Refused("destination is a symlink or reparse point")
	}
	// The staging root is private until now; the published tree gets the
	// same mode as its subdirectories.
	if err := osfs.SetPublishedRootMode(s.path); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "destination could not be published")
	}
	if !s.overwrite || !dinfo.Exist {
		err := osfs.RenameNoReplace(s.path, destAbs)
		switch {
		case err == nil:
			return nil
		case err == osfs.ErrDestinationExists:
			return transfercore.Fail(transfercore.ClassExists, "destination already exists")
		case err == osfs.ErrRenameNoReplaceUnsupported:
			// Absence-check-then-rename fallback is racy, per the spec.
			if dinfo.Exist {
				return transfercore.Fail(transfercore.ClassExists, "destination already exists")
			}
			if err := renameFunc(s.path, destAbs); err != nil {
				return transfercore.Fail(transfercore.ClassInternal, "destination could not be published")
			}
			return nil
		default:
			return transfercore.Fail(transfercore.ClassInternal, "destination could not be published")
		}
	}
	// Overwrite of an existing directory: rename aside, rename in, remove
	// the old tree, restore on failure.
	aside, err := s.asideName()
	if err != nil {
		return err
	}
	if err := renameFunc(destAbs, aside); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "existing destination could not be moved aside")
	}
	if err := renameFunc(s.path, destAbs); err != nil {
		if restoreErr := renameFunc(aside, destAbs); restoreErr != nil {
			// The old directory stays at the recognizable aside path.
			return transfercore.Fail(transfercore.ClassInternal, "publication failed and the previous destination could not be restored")
		}
		return transfercore.Fail(transfercore.ClassInternal, "destination could not be published")
	}
	_ = removeTree(aside)
	return nil
}

// asideName finds an absent staging-pattern name for the rename-aside step.
func (s *Staging) asideName() (string, error) {
	for attempt := 0; attempt < 5; attempt++ {
		suffix, err := pathsafe.RandomHex(12)
		if err != nil {
			return "", transfercore.Fail(transfercore.ClassInternal, "destination could not be replaced")
		}
		candidate := filepath.Join(s.parent, pathsafe.StagingPrefix+suffix)
		info, err := osfs.StatPath(candidate)
		if err != nil {
			return "", pathsafe.Refused("destination cannot be inspected")
		}
		if !info.Exist {
			return candidate, nil
		}
	}
	return "", transfercore.Fail(transfercore.ClassInternal, "destination could not be replaced")
}
