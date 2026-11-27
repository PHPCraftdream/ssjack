//go:build windows

package discovery

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func isReparse(info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
		return true
	}
	data, ok := info.Sys().(*windows.Win32FileAttributeData)
	return ok && data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func handleIsReparse(file *os.File) bool {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return true
	}
	return info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// resolveRoot returns the real directory behind path, including junctions that
// filepath.EvalSymlinks leaves in place.
func resolveRoot(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	name, err := windows.UTF16PtrFromString(resolved)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || length == 0 || int(length) >= len(buffer) {
		return "", errors.New("final path unavailable")
	}
	return filepath.Clean(trimExtendedPrefix(windows.UTF16ToString(buffer[:length]))), nil
}

// trimExtendedPrefix turns the \\?\ and \\?\UNC\ forms that GetFinalPathNameByHandle
// returns into ordinary drive and UNC paths, which the owner wire format accepts.
func trimExtendedPrefix(final string) string {
	const unc, extended = `\\?\UNC\`, `\\?\`
	switch {
	case strings.HasPrefix(final, unc):
		return `\\` + final[len(unc):]
	case strings.HasPrefix(final, extended):
		return final[len(extended):]
	}
	return final
}
