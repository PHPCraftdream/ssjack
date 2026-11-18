//go:build !windows

package terminal

func PrepareTerminalOutput(_ int) (func() error, error) {
	return func() error { return nil }, nil
}
