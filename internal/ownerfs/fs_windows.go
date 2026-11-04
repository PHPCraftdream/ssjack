package ownerfs

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/sys/windows"
)

func relative(root *os.File, name string, directory, create, writable bool) (*os.File, error) {
	if name == "" || (name == "." && (!directory || create)) || name == ".." || strings.ContainsAny(name, "\\/:\x00") {
		return nil, ErrInvalid
	}
	unicode, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, ErrInvalid
	}
	attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(reflect.TypeOf(windows.OBJECT_ATTRIBUTES{}).Size()), RootDirectory: windows.Handle(root.Fd()), ObjectName: unicode, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	if create {
		attributes.SecurityDescriptor, _, err = descriptor()
		if err != nil {
			return nil, err
		}
	}
	access := uint32(windows.GENERIC_READ | windows.SYNCHRONIZE | windows.READ_CONTROL)
	if create || writable {
		access |= windows.GENERIC_WRITE | windows.DELETE
	}
	options := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	fileAttributes := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
		fileAttributes = windows.FILE_ATTRIBUTE_DIRECTORY
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE | windows.FILE_WRITE_THROUGH
	}
	disposition := uint32(windows.FILE_OPEN)
	if create {
		disposition = windows.FILE_CREATE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attributes, &status, nil, fileAttributes,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, options, 0, 0)
	if err != nil {
		return nil, mapError(err)
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, ErrUnavailable
	}
	return file, nil
}

func walk(path string, protected bool) (*os.File, error) {
	if !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrInvalid
	}
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return nil, ErrUnsupported
	}
	rootName, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil || windows.GetDriveType(rootName) != windows.DRIVE_FIXED {
		return nil, ErrUnsupported
	}
	handle, err := windows.CreateFile(rootName, windows.GENERIC_READ|windows.SYNCHRONIZE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, mapError(err)
	}
	file := os.NewFile(uintptr(handle), volume+`\`)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, ErrUnavailable
	}
	if diskDirectory(file) != nil || localNTFS(file) != nil {
		file.Close()
		return nil, ErrUnsupported
	}
	relativePath := strings.TrimPrefix(path[len(volume):], `\`)
	if relativePath == "" {
		if protected {
			file.Close()
			return nil, ErrInvalid
		}
		return file, nil
	}
	for _, name := range strings.Split(relativePath, `\`) {
		next, err := relative(file, name, true, false, false)
		file.Close()
		if err != nil {
			return nil, err
		}
		file = next
		if diskDirectory(file) != nil {
			file.Close()
			return nil, ErrInvalid
		}
	}
	if protected {
		if metadata, err := stat(file, false); err != nil || !metadata.Directory {
			file.Close()
			return nil, ErrInvalid
		}
	}
	return file, nil
}
func openRoot(path string) (*Root, error) {
	file, err := walk(path, true)
	if err != nil {
		return nil, err
	}
	return &Root{file: file}, nil
}
func duplicate(file *os.File) (*os.File, error) {
	var handle windows.Handle
	process := windows.CurrentProcess()
	if err := windows.DuplicateHandle(process, windows.Handle(file.Fd()), process, &handle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, ErrUnavailable
	}
	owned := os.NewFile(uintptr(handle), file.Name())
	if owned == nil {
		windows.CloseHandle(handle)
		return nil, ErrUnavailable
	}
	return owned, nil
}
func adoptRoot(file *os.File) (*Root, error) {
	before, err := stat(file, false)
	if err != nil || !before.Directory || localNTFS(file) != nil {
		return nil, ErrInvalid
	}
	owned, err := duplicate(file)
	if err != nil {
		return nil, err
	}
	after, err := stat(owned, false)
	if err != nil || after.Dev != before.Dev || after.Ino != before.Ino {
		owned.Close()
		return nil, ErrChanged
	}
	return &Root{file: owned}, nil
}
func makeRoot(path string) (*Root, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	parent, err := walk(filepath.Dir(filepath.Clean(path)), false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	file, err := relative(parent, filepath.Base(path), true, true, true)
	if err != nil {
		return nil, err
	}
	if metadata, err := stat(file, false); err != nil || !metadata.Directory {
		file.Close()
		return nil, ErrInvalid
	}
	return &Root{file: file}, nil
}
func child(root *os.File, name string, create bool) (*Root, error) {
	file, err := relative(root, name, true, create, true)
	if create && err == ErrExists {
		file, err = relative(root, name, true, false, true)
	}
	if err != nil {
		return nil, err
	}
	if metadata, err := stat(file, false); err != nil || !metadata.Directory {
		file.Close()
		return nil, ErrInvalid
	}
	return &Root{file: file}, nil
}
func openFile(root *os.File, name string, writable, exclusive bool) (*os.File, error) {
	file, err := relative(root, name, false, exclusive, writable)
	if err != nil {
		return nil, err
	}
	if metadata, err := stat(file, false); err != nil || metadata.Directory {
		file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}
