package ownerfs

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func mapError(err error) error {
	if err == nil {
		return nil
	}
	var status windows.NTStatus
	if errors.As(err, &status) {
		err = status.Errno()
	}
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND), errors.Is(err, windows.ERROR_DELETE_PENDING):
		return ErrMissing
	case errors.Is(err, windows.ERROR_FILE_EXISTS), errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return ErrExists
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION), errors.Is(err, windows.ERROR_SHARING_VIOLATION):
		return ErrBusy
	case errors.Is(err, windows.ERROR_NOT_SUPPORTED), errors.Is(err, windows.ERROR_INVALID_FUNCTION):
		return ErrUnsupported
	}
	return ErrUnavailable
}
func descriptor() (*windows.SECURITY_DESCRIPTOR, string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, "", ErrUnavailable
	}
	sid := user.User.Sid.String()
	if sid == "" {
		return nil, "", ErrUnavailable
	}
	value, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
	return value, sid, mapError(err)
}
func private(file *os.File) error {
	expected, sid, err := descriptor()
	if err != nil {
		return err
	}
	actual, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || actual == nil {
		return ErrInvalid
	}
	owner, _, err := actual.Owner()
	if err != nil || owner == nil || owner.String() != sid {
		return ErrInvalid
	}
	control, _, err := actual.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrInvalid
	}
	acl, _, err := actual.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		return ErrInvalid
	}
	aces := func(sd *windows.SECURITY_DESCRIPTOR) string {
		text := sd.String()
		if start := strings.IndexByte(text, '('); start >= 0 {
			return text[start:]
		}
		return ""
	}
	if wanted := aces(expected); wanted == "" || aces(actual) != wanted {
		return ErrInvalid
	}
	return nil
}
func fileTime(value uint64) (int64, int64, bool) {
	if value > math.MaxInt64 {
		return 0, 0, false
	}
	ticks := int64(value) - 116444736000000000
	seconds, remainder := ticks/10000000, ticks%10000000
	if remainder < 0 {
		seconds--
		remainder += 10000000
	}
	return seconds, remainder * 100, true
}
func stat(file *os.File, anonymous bool) (Metadata, error) {
	if file == nil {
		return Metadata{}, ErrInvalid
	}
	handle := windows.Handle(file.Fd())
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK || private(file) != nil {
		return Metadata{}, ErrInvalid
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return Metadata{}, ErrInvalid
	}
	directory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	links := uint32(1)
	if anonymous {
		links = 0
	}
	if (directory && (anonymous || info.NumberOfLinks == 0)) || (!directory && info.NumberOfLinks != links) {
		return Metadata{}, ErrInvalid
	}
	size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if size > math.MaxInt64 {
		return Metadata{}, ErrInvalid
	}
	var basic [40]byte
	if windows.GetFileInformationByHandleEx(handle, 0, &basic[0], uint32(len(basic))) != nil {
		return Metadata{}, ErrUnavailable
	}
	mtime, mnano, valid := fileTime(binary.LittleEndian.Uint64(basic[16:24]))
	ctime, cnano, changed := fileTime(binary.LittleEndian.Uint64(basic[24:32]))
	if !valid || !changed {
		return Metadata{}, ErrInvalid
	}
	dev, ino := uint64(info.VolumeSerialNumber), uint64(info.FileIndexHigh)<<32|uint64(info.FileIndexLow)
	if dev == 0 || ino == 0 {
		return Metadata{}, ErrUnsupported
	}
	return Metadata{Dev: dev, Ino: ino, Links: uint64(info.NumberOfLinks), Size: int64(size), MtimeSec: mtime, MtimeNsec: mnano, CtimeSec: ctime, CtimeNsec: cnano, Directory: directory}, nil
}

func diskDirectory(file *os.File) error {
	kind, err := windows.GetFileType(windows.Handle(file.Fd()))
	var info windows.ByHandleFileInformation
	if err != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalid
	}
	return nil
}
func localNTFS(file *os.File) error {
	var name [32]uint16
	if windows.GetVolumeInformationByHandle(windows.Handle(file.Fd()), nil, 0, nil, nil, nil, &name[0], uint32(len(name))) != nil || windows.UTF16ToString(name[:]) != "NTFS" {
		return ErrUnsupported
	}
	return nil
}
