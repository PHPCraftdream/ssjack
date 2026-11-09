// Package ownerpublication persists prepared encrypted-file publications.
package ownerpublication

import (
	"errors"
	"os"
)

// Replace publishes an already flushed same-volume staging file, without fallback.
func Replace(source, destination string) error { return replace(source, destination) }

// Sync never writes file contents; the caller verifies ciphertext before and after.
func Sync(path string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return errors.New("encrypted publication must be a regular file")
	}
	return syncPublication(path, before)
}
