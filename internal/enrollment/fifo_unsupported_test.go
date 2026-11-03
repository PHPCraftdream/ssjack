//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !solaris

package enrollment

func makeFIFO(string) error { return errUnsupportedPlatform }
