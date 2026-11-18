//go:build windows

package osfs

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"

	"golang.org/x/sys/windows"
)

// PathInfo is the no-follow inspection result for one path.
type PathInfo struct {
	Exist       bool
	Dir         bool
	Regular     bool
	Reparse     bool // any reparse point: symlink, junction, mount point
	MultiLinked bool // never reported on windows; hard links are not verified here
	Size        int64
	Mode        os.FileMode
}

// wideLocalPath prefixes an absolute path with \\?\ (\\?\UNC for shares) so
// Win32 APIs see the literal name.
func wideLocalPath(path string) (*uint16, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("path is not absolute")
	}
	absolute := filepath.Clean(path)
	if hasPrefix(absolute, `\\?\`) {
		return windows.UTF16PtrFromString(absolute)
	}
	if hasPrefix(absolute, `\\`) {
		absolute = `\\?\UNC\` + absolute[2:]
	} else {
		absolute = `\\?\` + absolute
	}
	return windows.UTF16PtrFromString(absolute)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func notFoundError(err error) bool {
	return err != nil && (errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND))
}

func existsError(err error) bool {
	return err != nil && (errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS))
}

// StatPath inspects path without following reparse points. A missing path
// returns PathInfo{exist:false} and a nil error.
func StatPath(path string) (PathInfo, error) {
	info := PathInfo{}
	name, err := wideLocalPath(path)
	if err != nil {
		return PathInfo{}, err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		if notFoundError(err) {
			return PathInfo{}, nil
		}
		return PathInfo{}, err
	}
	info.Exist = true
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.Reparse = true
		return info, nil
	}
	raw, err := os.Lstat(path)
	if err != nil {
		return PathInfo{}, err
	}
	info.Dir = attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	info.Regular = !info.Dir
	info.Size = raw.Size()
	// Windows has no owner-execute bit, so modes are normalized.
	if info.Dir {
		info.Mode = os.ModeDir | 0755
	} else {
		info.Mode = 0644
	}
	return info, nil
}

// PathIdentity returns a stable per-file identity string used to verify that
// a staging path still holds the object this job created.
func PathIdentity(path string) (string, error) {
	name, err := wideLocalPath(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.New("path is a reparse point")
	}
	return strconv.FormatUint(uint64(info.VolumeSerialNumber), 10) + ":" +
		strconv.FormatUint(uint64(info.FileIndexHigh), 10) + ":" +
		strconv.FormatUint(uint64(info.FileIndexLow), 10), nil
}

// OpenRegularNoFollow opens an existing regular file without following
// reparse points and verifies regularness on the open handle.
func OpenRegularNoFollow(path string) (*os.File, int64, error) {
	name, err := wideLocalPath(path)
	if err != nil {
		return nil, 0, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, 0, err
	}
	file, size, err := regularFromHandle(handle, path)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, 0, err
	}
	return file, size, nil
}

// regularFromHandle verifies that an open handle is a regular disk file and
// wraps it.
func regularFromHandle(handle windows.Handle, path string) (*os.File, int64, error) {
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK {
		return nil, 0, errors.New("path is not a regular file")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, 0, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, 0, errors.New("path is not a regular file")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, 0, errors.New("cannot adopt the file handle")
	}
	return file, int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)), nil
}

// CreateExclusiveFile creates a new regular file exclusively.
func CreateExclusiveFile(path string, mode os.FileMode) (*os.File, error) {
	name, err := wideLocalPath(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if existsError(err) {
			return nil, ErrDestinationExists
		}
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errors.New("cannot adopt the file handle")
	}
	return file, nil
}

// CreatePrivateDir creates a directory exclusively with an owner-only DACL,
// matching internal/ownerarchive/private_windows.go.
func CreatePrivateDir(path string) error {
	descriptor, err := privateDescriptor()
	if err != nil {
		return err
	}
	name, err := wideLocalPath(path)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(reflect.TypeOf(windows.SecurityAttributes{}).Size()),
		SecurityDescriptor: descriptor,
	}
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		if existsError(err) {
			return ErrDestinationExists
		}
		return err
	}
	return nil
}

// privateDescriptor builds a protected owner-only security descriptor.
func privateDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, errors.New("cannot identify the process user")
	}
	sid := user.User.Sid.String()
	if sid == "" {
		return nil, errors.New("cannot identify the process user")
	}
	return windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
}

// CreateStageDir creates the keyed chunk staging directory exclusively with an
// owner-only DACL.
func CreateStageDir(path string) error {
	return CreatePrivateDir(path)
}

// PrivateOwnedDir reports whether the directory is owned by the process user
// (CreatePrivateDir records that owner explicitly) or by the Administrators
// group, which an elevated process may be given as the default owner. Windows
// has no mode bits, so there is nothing else to compare.
func PrivateOwnedDir(path string, info PathInfo) bool {
	name, err := wideLocalPath(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil && owner.Equals(user.User.Sid) {
		return true
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	return err == nil && owner.Equals(admins)
}

// SetPublishedRootMode is a no-op on Windows: modes do not exist there, and
// widening the private ACL of the staging root is a separate decision.
func SetPublishedRootMode(string) error { return nil }

// SyncDirectory is a no-op on windows: directory entry lists cannot be
// flushed portably, MOVEFILE_WRITE_THROUGH provides ordering instead.
func SyncDirectory(path string) error {
	return nil
}

// SyncPathData flushes the data of an existing regular file opened without
// following reparse points.
func SyncPathData(path string) error {
	name, err := wideLocalPath(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK {
		windows.CloseHandle(handle)
		return errors.New("path is not a regular file")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(handle)
		return errors.New("path is not a regular file")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return errors.New("cannot adopt the file handle")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// HardLinkNoClobber creates target as a hard link to existing.
func HardLinkNoClobber(existing, target string) error {
	existingName, err := wideLocalPath(existing)
	if err != nil {
		return err
	}
	targetName, err := wideLocalPath(target)
	if err != nil {
		return err
	}
	if err := windows.CreateHardLink(targetName, existingName, 0); err != nil {
		if existsError(err) {
			return ErrDestinationExists
		}
		if errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
			return ErrHardLinkUnsupported
		}
		return err
	}
	return nil
}

// RenameReplaceFile atomically replaces an existing regular file at target
// with source.
func RenameReplaceFile(source, target string) error {
	sourceName, err := wideLocalPath(source)
	if err != nil {
		return err
	}
	targetName, err := wideLocalPath(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourceName, targetName, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
