//go:build !windows

package ownerarchive

import (
	"errors"
	"os"
)

func newPrivateFile(destination string) (*os.File, error) {
	return os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

func checkPrivateFile(_ *os.File, identity os.FileInfo) error {
	if !identity.Mode().IsRegular() || identity.Mode().Perm() != 0600 {
		return errors.New("owner export file permissions are not private")
	}
	return nil
}
