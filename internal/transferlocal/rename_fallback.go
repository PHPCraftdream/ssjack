//go:build !windows && !linux && !darwin

package transferlocal

// renameNoReplace has no atomic no-replace primitive on other platforms.
func renameNoReplace(source, target string) error {
	return errRenameNoReplaceUnsupported
}
