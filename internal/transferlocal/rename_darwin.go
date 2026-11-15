//go:build darwin

package transferlocal

import (
	"errors"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames source to target atomically without replacing an
// existing target, using RENAME_EXCL.
func renameNoReplace(source, target string) error {
	err := unix.RenameatxNp(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_EXCL)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, unix.EEXIST):
		return errDestinationExists
	case errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.EOPNOTSUPP):
		return errRenameNoReplaceUnsupported
	}
	return err
}
