//go:build linux

package transferlocal

import (
	"errors"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames source to target atomically without replacing an
// existing target. EINVAL means this kernel or filesystem has no
// RENAME_NOREPLACE support.
func renameNoReplace(source, target string) error {
	err := unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, unix.EEXIST):
		return errDestinationExists
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
		return errRenameNoReplaceUnsupported
	}
	return err
}
