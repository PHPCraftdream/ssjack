//go:build linux

package recoveryjournal

import (
	"errors"
	"os"
)

type diskIO struct {
	create  func(string) (*os.File, error)
	write   func(*os.File, []byte) error
	sync    func(*os.File) error
	close   func(*os.File) error
	rename  func(string, string) error
	remove  func(string) error
	syncDir func(string) error
}

func supported() bool { return true }

func syncDirectory(path string, open func(string) (*os.File, error), syncFile func(*os.File) error, closeFile func(*os.File) error) error {
	f, err := open(path)
	if err != nil {
		return err
	}
	syncErr := syncFile(f)
	closeErr := closeFile(f)
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func systemIO() diskIO {
	return diskIO{
		create: func(p string) (*os.File, error) { return os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) },
		write: func(f *os.File, b []byte) error {
			for len(b) > 0 {
				n, e := f.Write(b)
				if e != nil {
					return e
				}
				if n == 0 {
					return errors.New("short write")
				}
				b = b[n:]
			}
			return nil
		},
		sync:   func(f *os.File) error { return f.Sync() },
		close:  func(f *os.File) error { return f.Close() },
		rename: os.Rename,
		remove: os.Remove,
		syncDir: func(p string) error {
			return syncDirectory(p, os.Open, func(f *os.File) error { return f.Sync() }, func(f *os.File) error { return f.Close() })
		},
	}
}
