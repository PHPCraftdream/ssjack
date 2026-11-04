package ownerfscheck

import (
	"errors"

	"golang.org/x/sys/windows"
)

func inaccessible(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// Match native delete sharing; ordinary os.Open can fail for unrelated sharing.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == nil {
		windows.CloseHandle(handle)
		return errors.New("anonymous spool is readable through a native filesystem path")
	}
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, windows.ERROR_DELETE_PENDING) {
		return nil
	}
	return errors.New("native anonymous spool lookup did not prove pathname absence")
}
