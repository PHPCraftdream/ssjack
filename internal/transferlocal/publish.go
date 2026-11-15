package transferlocal

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
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
	payload := filepath.Join(s.path, payloadName)
	info, err := statPath(payload)
	if err != nil || !info.exist {
		return transfercore.Fail(transfercore.ClassInternal, "staging payload is missing")
	}
	if !info.regular || info.reparse {
		return transfercore.Fail(transfercore.ClassInternal, "staging payload is not a regular file")
	}
	if err := syncPathData(payload); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "staged data could not be flushed")
	}
	dinfo, err := statPath(destAbs)
	if err != nil {
		return refusedPath("destination cannot be inspected")
	}
	if dinfo.reparse {
		return refusedPath("destination is a symlink or reparse point")
	}
	if !s.overwrite {
		err := hardLinkNoClobber(payload, destAbs)
		switch {
		case err == nil:
			return nil
		case err == errDestinationExists:
			return transfercore.Fail(transfercore.ClassExists, "destination already exists")
		case err == errHardLinkUnsupported:
			// Existence-check-then-rename fallback is racy, per the spec.
			if dinfo.exist {
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
	if dinfo.exist && dinfo.dir {
		return refusedPath("destination is a directory")
	}
	if dinfo.exist && !dinfo.regular {
		return refusedPath("destination is not a regular file")
	}
	if err := renameReplaceFile(payload, destAbs); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "destination could not be replaced")
	}
	return nil
}

// publishDir publishes the staged tree at destAbs by rename only.
func (s *Staging) publishDir(destAbs string) error {
	dinfo, err := statPath(destAbs)
	if err != nil {
		return refusedPath("destination cannot be inspected")
	}
	if dinfo.reparse {
		return refusedPath("destination is a symlink or reparse point")
	}
	// The staging root is private until now; the published tree gets the
	// same mode as its subdirectories.
	if err := setPublishedRootMode(s.path); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "destination could not be published")
	}
	if !s.overwrite || !dinfo.exist {
		err := renameNoReplace(s.path, destAbs)
		switch {
		case err == nil:
			return nil
		case err == errDestinationExists:
			return transfercore.Fail(transfercore.ClassExists, "destination already exists")
		case err == errRenameNoReplaceUnsupported:
			// Absence-check-then-rename fallback is racy, per the spec.
			if dinfo.exist {
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
		suffix, err := randomHex(12)
		if err != nil {
			return "", transfercore.Fail(transfercore.ClassInternal, "destination could not be replaced")
		}
		candidate := filepath.Join(s.parent, stagingPrefix+suffix)
		info, err := statPath(candidate)
		if err != nil {
			return "", refusedPath("destination cannot be inspected")
		}
		if !info.exist {
			return candidate, nil
		}
	}
	return "", transfercore.Fail(transfercore.ClassInternal, "destination could not be replaced")
}
