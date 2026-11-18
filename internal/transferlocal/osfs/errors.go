// Package osfs holds the platform-specific no-follow filesystem primitives of
// transferlocal: inspection, exclusive creation, syncing, hard links and
// atomic renames. Platform code lives in *_unix.go, *_windows.go and the
// rename_<os>.go files.
package osfs

import "errors"

// Raw internal sentinels. They are classified and converted into
// *transfercore.Error values by boundary functions and never returned as-is.
var (
	ErrDestinationExists          = errors.New("transfer destination already exists")
	ErrHardLinkUnsupported        = errors.New("hard links are not supported on this filesystem")
	ErrRenameNoReplaceUnsupported = errors.New("atomic no-replace rename is unavailable on this platform")
)
