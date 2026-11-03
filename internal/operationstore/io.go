package operationstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

type publicationIO struct {
	createFile func(string, int, os.FileMode) (*os.File, error)
	writeFile  func(*os.File, []byte) error
	syncFile   func(*os.File) error
	closeFile  func(*os.File) error
	rename     func(string, string) error
	syncDir    func(string) error
	remove     func(string) error
}

func systemPublicationIO() publicationIO {
	return publicationIO{
		createFile: func(path string, flags int, mode os.FileMode) (*os.File, error) {
			return os.OpenFile(path, flags, mode)
		},
		writeFile: func(f *os.File, b []byte) error {
			for len(b) > 0 {
				n, err := f.Write(b)
				if err != nil {
					return err
				}
				if n == 0 {
					return errors.New("short write")
				}
				b = b[n:]
			}
			return nil
		},
		syncFile:  func(f *os.File) error { return f.Sync() },
		closeFile: func(f *os.File) error { return f.Close() },
		rename:    os.Rename, syncDir: syncDirectory, remove: os.Remove,
	}
}

func (s *Store) publication() publicationIO {
	p, d := s.io, systemPublicationIO()
	if p.createFile != nil {
		d.createFile = p.createFile
	}
	if p.writeFile != nil {
		d.writeFile = p.writeFile
	}
	if p.syncFile != nil {
		d.syncFile = p.syncFile
	}
	if p.closeFile != nil {
		d.closeFile = p.closeFile
	}
	if p.rename != nil {
		d.rename = p.rename
	}
	if p.syncDir != nil {
		d.syncDir = p.syncDir
	}
	if p.remove != nil {
		d.remove = p.remove
	}
	return d
}

func publicationSupported() bool { return runtime.GOOS == "linux" }

func syncParentDirectory(root string) error { return syncDirectory(filepath.Dir(root)) }
