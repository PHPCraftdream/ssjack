package ownerfs

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"

	"golang.org/x/sys/windows"
)

func lock(root *os.File, name string) (func() error, error) {
	file, err := openFile(root, name, true, false)
	if errors.Is(err, ErrMissing) {
		file, err = openFile(root, name, true, true)
	}
	if errors.Is(err, ErrExists) {
		file, err = openFile(root, name, true, false)
	}
	if err != nil {
		return nil, err
	}
	metadata, err := stat(file, false)
	if err != nil || metadata.Size != 0 || metadata.Directory {
		file.Close()
		return nil, ErrInvalid
	}
	position := windows.Overlapped{}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &position); err != nil {
		file.Close()
		return nil, mapError(err)
	}
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			result = mapError(windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &position))
			if err := file.Close(); result == nil && err != nil {
				result = ErrUnavailable
			}
		})
		return result
	}, nil
}

func discard(file *os.File) error {
	var flags [4]byte
	binary.LittleEndian.PutUint32(flags[:], 3) // DELETE | POSIX_SEMANTICS, not ON_CLOSE.
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtSetInformationFile(windows.Handle(file.Fd()), &status, &flags[0], uint32(len(flags)), windows.FileDispositionInformationEx); err != nil {
		return mapError(err)
	}
	return nil
}
func temporary(root *os.File) (*os.File, error) {
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, ErrUnavailable
	}
	name := ".spool-" + hex.EncodeToString(identity[:]) + ".tmp"
	file, err := openFile(root, name, true, true)
	if err != nil {
		return nil, err
	}
	// Detach the empty name before any caller can write ciphertext.
	if err := discard(file); err != nil {
		file.Close()
		return nil, err
	}
	metadata, err := stat(file, true)
	if err != nil || metadata.Size != 0 || metadata.Directory {
		file.Close()
		return nil, ErrUnsupported
	}
	return file, nil
}
func remove(root *os.File, name string) error {
	file, err := openFile(root, name, true, false)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := discard(file); err != nil {
		return err
	}
	return nil
}
func flush(root *os.File, name string) error {
	file, err := openFile(root, name, true, false)
	if err != nil {
		return err
	}
	defer file.Close()
	// Native write-through handles plus file flush; not a directory-fsync claim.
	if err := file.Sync(); err != nil {
		return ErrUncertain
	}
	return nil
}

func rename(source *os.File, name string, destination *os.File, target string, replace bool) error {
	file, err := openFile(source, name, true, false)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := stat(file, false)
	if err != nil || before.Directory {
		return ErrInvalid
	}
	type renameInfo struct {
		Replace byte
		Root    windows.Handle
		Length  uint32
		Name    [1]uint16
	}
	layout := reflect.TypeOf(renameInfo{})
	rootField, _ := layout.FieldByName("Root")
	lengthField, _ := layout.FieldByName("Length")
	nameField, _ := layout.FieldByName("Name")
	if reflect.TypeOf(windows.Handle(0)).Size() != 8 {
		return ErrUnsupported
	}
	unicode, err := windows.UTF16FromString(target)
	if err != nil || len(unicode) > 129 {
		return ErrInvalid
	}
	unicode = unicode[:len(unicode)-1]
	encoded := make([]byte, int(nameField.Offset)+len(unicode)*2)
	if replace {
		encoded[0] = 1
	}
	binary.LittleEndian.PutUint64(encoded[int(rootField.Offset):], uint64(destination.Fd()))
	binary.LittleEndian.PutUint32(encoded[int(lengthField.Offset):], uint32(len(unicode)*2))
	for i, value := range unicode {
		binary.LittleEndian.PutUint16(encoded[int(nameField.Offset)+i*2:], value)
	}
	var status windows.IO_STATUS_BLOCK
	// FileRenameInformation has a handle-relative destination and explicit replacement.
	if err := windows.NtSetInformationFile(windows.Handle(file.Fd()), &status, &encoded[0], uint32(len(encoded)), 10); err != nil {
		return mapError(err)
	}
	if err := file.Sync(); err != nil {
		return ErrUncertain
	}
	published, err := openFile(destination, target, false, false)
	if err != nil {
		return ErrUncertain
	}
	defer published.Close()
	after, err := stat(published, false)
	if err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.MtimeSec != before.MtimeSec || after.MtimeNsec != before.MtimeNsec {
		return ErrUncertain
	}
	return nil
}

func entries(root *os.File, visit func(string) error) error {
	file, err := relative(root, ".", true, false, false)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := stat(root, false)
	if err != nil {
		return err
	}
	actual, err := stat(file, false)
	if err != nil || actual.Dev != before.Dev || actual.Ino != before.Ino {
		return ErrChanged
	}
	count := 0
	for {
		batch, err := file.ReadDir(256)
		for _, entry := range batch {
			count++
			if count > 1<<20 || !atom(entry.Name()) {
				return ErrInvalid
			}
			if err := visit(entry.Name()); err != nil {
				return err
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return ErrUnavailable
		}
	}
}
