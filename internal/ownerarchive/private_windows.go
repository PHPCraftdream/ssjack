package ownerarchive

import (
	"errors"
	"os"
	"reflect"
	"strings"

	"golang.org/x/sys/windows"
)

func ownerDescriptor() (*windows.SECURITY_DESCRIPTOR, string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, "", errors.New("cannot identify owner export file user")
	}
	sid := user.User.Sid.String()
	if sid == "" {
		return nil, "", errors.New("invalid owner export file user")
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
	if err != nil {
		return nil, "", errors.New("cannot prepare a protected owner-only export ACL")
	}
	return descriptor, sid, nil
}

// openArchive opens an existing disk file for reading. The reparse point is
// opened itself (not followed) and then refused, and the type is checked on the
// open handle, so symlinks, pipes, devices, directories and swapped paths fail.
func openArchive(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrArchive
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ErrArchive
	}
	var info windows.ByHandleFileInformation
	kind, typeErr := windows.GetFileType(handle)
	if typeErr != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(handle, &info) != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(handle)
		return nil, ErrArchive
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, ErrArchive
	}
	return file, nil
}

func newPrivateFile(destination string) (*os.File, error) {
	descriptor, _, err := ownerDescriptor()
	if err != nil {
		return nil, err
	}
	path, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(reflect.TypeOf(windows.SecurityAttributes{}).Size()), SecurityDescriptor: descriptor}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), destination)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errors.New("cannot own the private export file handle")
	}
	return file, nil
}

func checkPrivateFile(file *os.File, identity os.FileInfo) error {
	if !identity.Mode().IsRegular() {
		return errors.New("owner export destination is not a regular file")
	}
	expected, sid, err := ownerDescriptor()
	if err != nil {
		return err
	}
	actual, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || actual == nil {
		return errors.New("cannot verify owner export file ACL")
	}
	owner, _, err := actual.Owner()
	if err != nil || owner == nil || owner.String() != sid {
		return errors.New("owner export file has another owner")
	}
	control, _, err := actual.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("owner export file ACL permits inheritance")
	}
	acl, _, err := actual.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		return errors.New("owner export file ACL is not owner-only")
	}
	entries := func(descriptor *windows.SECURITY_DESCRIPTOR) string {
		text := descriptor.String()
		start := strings.IndexByte(text, '(')
		if start < 0 {
			return ""
		}
		return text[start:]
	}
	wanted := entries(expected)
	if wanted == "" || entries(actual) != wanted {
		return errors.New("owner export file ACL grants unexpected access")
	}
	return nil
}
