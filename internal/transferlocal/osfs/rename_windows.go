//go:build windows

package osfs

import "golang.org/x/sys/windows"

// RenameNoReplace moves source to target; MoveFileEx without
// MOVEFILE_REPLACE_EXISTING fails when target already exists.
func RenameNoReplace(source, target string) error {
	sourceName, err := wideLocalPath(source)
	if err != nil {
		return err
	}
	targetName, err := wideLocalPath(target)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(sourceName, targetName, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		if existsError(err) {
			return ErrDestinationExists
		}
		return err
	}
	return nil
}
