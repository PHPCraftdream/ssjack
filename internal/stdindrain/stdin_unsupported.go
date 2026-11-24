//go:build !windows && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package stdindrain

func drainPlatform() error { return ErrDrain }
