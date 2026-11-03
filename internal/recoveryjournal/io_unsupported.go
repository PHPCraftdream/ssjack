//go:build !linux

package recoveryjournal

import "os"

type diskIO struct {
	create  func(string) (*os.File, error)
	write   func(*os.File, []byte) error
	sync    func(*os.File) error
	close   func(*os.File) error
	rename  func(string, string) error
	remove  func(string) error
	syncDir func(string) error
}

func supported() bool  { return false }
func systemIO() diskIO { return diskIO{} }
