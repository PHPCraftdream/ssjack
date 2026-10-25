//go:build !windows

package main

func prepareTerminalOutput(_ int) (func() error, error) {
	return func() error { return nil }, nil
}
