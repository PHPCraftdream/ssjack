//go:build !windows && !linux && !darwin

package osfs

// RenameNoReplace has no atomic no-replace primitive on other platforms.
func RenameNoReplace(source, target string) error {
	return ErrRenameNoReplaceUnsupported
}
