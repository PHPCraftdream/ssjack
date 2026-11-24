//go:build !windows

package discovery

import (
	"os"
)

func isReparse(os.FileInfo) bool { return false }

func handleIsReparse(file *os.File) bool { return false }
