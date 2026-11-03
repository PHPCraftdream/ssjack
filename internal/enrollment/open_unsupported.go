//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !solaris

package enrollment

import (
	"errors"
	"os"
)

var errUnsupportedPlatform = errors.New("secure enrollment file loading is unsupported on this platform")

func openSafeFile(string) (*os.File, error) {
	return nil, errUnsupportedPlatform
}
