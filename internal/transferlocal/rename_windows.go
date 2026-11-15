//go:build windows

package transferlocal

import "golang.org/x/sys/windows"

// renameNoReplace moves source to target; MoveFileEx without
// MOVEFILE_REPLACE_EXISTING fails when target already exists.
func renameNoReplace(source, target string) error {
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
			return errDestinationExists
		}
		return err
	}
	return nil
}
