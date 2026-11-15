package transferlocal

import "errors"

// Raw internal sentinels. They are classified and converted into
// *transfercore.Error values by boundary functions and never returned as-is.
var (
	errDestinationExists          = errors.New("transfer destination already exists")
	errHardLinkUnsupported        = errors.New("hard links are not supported on this filesystem")
	errRenameNoReplaceUnsupported = errors.New("atomic no-replace rename is unavailable on this platform")
)
