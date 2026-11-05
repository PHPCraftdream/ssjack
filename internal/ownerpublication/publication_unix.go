//go:build !windows

package ownerpublication

import (
	"os"
	"path/filepath"
)

func replace(source, destination string) error { return os.Rename(source, destination) }

func syncPublication(path string, _ os.FileInfo) error {
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
