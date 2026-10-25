//go:build windows

package main

import "golang.org/x/sys/windows"

func prepareTerminalOutput(fd int) (func() error, error) {
	handle := windows.Handle(fd)
	var previous uint32
	if err := windows.GetConsoleMode(handle, &previous); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(handle, previous|windows.ENABLE_PROCESSED_OUTPUT|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return nil, err
	}
	return func() error { return windows.SetConsoleMode(handle, previous) }, nil
}
