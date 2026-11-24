//go:build !windows

package discovery

import (
	"os"
	"path/filepath"
)

func isReparse(os.FileInfo) bool { return false }

func handleIsReparse(file *os.File) bool { return false }

func resolveRoot(path string) (string, error) { return filepath.EvalSymlinks(path) }
