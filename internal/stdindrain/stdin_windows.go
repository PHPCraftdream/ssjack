//go:build windows

package stdindrain

import (
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var peekNamedPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")
var readConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")

type consoleInputRecord struct {
	eventType uint16
	padding   uint16
	event     [16]byte
}

func drainPlatform() error {
	h := windows.Handle(os.Stdin.Fd())
	state, err := windows.GetFileType(h)
	if err != nil {
		return ErrDrain
	}
	if state == windows.FILE_TYPE_PIPE {
		return drainPipe(h)
	}
	if state != windows.FILE_TYPE_CHAR {
		return ErrDrain
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return ErrDrain
	}
	return drainConsole(h)
}

func drainConsole(h windows.Handle) error {
	deadline := time.Now().Add(IdleWindow)
	overallDeadline := time.Now().Add(MaxDuration)
	consumed := uint32(0)
	for {
		if time.Until(overallDeadline) <= 0 {
			return ErrDrain
		}
		var available uint32
		if err := windows.GetNumberOfConsoleInputEvents(h, &available); err != nil {
			return ErrDrain
		}
		if time.Until(overallDeadline) <= 0 {
			return ErrDrain
		}
		if available != 0 {
			if consumed >= MaxBytes {
				return ErrDrain
			}
			count := min(available, uint32(256), uint32(MaxBytes)-consumed)
			records := make([]consoleInputRecord, count)
			var read uint32
			r, _, callErr := readConsoleInput.Call(uintptr(h), uintptr(unsafe.Pointer(&records[0])), uintptr(count), uintptr(unsafe.Pointer(&read)))
			if r == 0 || read == 0 || read > count {
				clear(records)
				if callErr == windows.ERROR_SUCCESS {
					return ErrDrain
				}
				return ErrDrain
			}
			clear(records)
			if time.Until(overallDeadline) <= 0 {
				return ErrDrain
			}
			consumed += read
			deadline = time.Now().Add(IdleWindow)
			continue
		}
		remaining := min(time.Until(deadline), time.Until(overallDeadline))
		if remaining <= 0 {
			if time.Until(overallDeadline) <= 0 {
				return ErrDrain
			}
			return nil
		}
		pause := time.Millisecond
		if remaining < pause {
			pause = remaining
		}
		time.Sleep(pause)
	}
}

func drainPipe(h windows.Handle) error {
	return Drain(IdleWindow, MaxBytes, func(wait time.Duration) (bool, error) {
		deadline := time.Now().Add(wait)
		for {
			var available uint32
			r, _, callErr := peekNamedPipe.Call(uintptr(h), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
			if r == 0 {
				if callErr != windows.ERROR_SUCCESS {
					return false, callErr
				}
				return false, windows.ERROR_INVALID_HANDLE
			}
			if available != 0 {
				return true, nil
			}
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return false, nil
			}
			pause := time.Millisecond
			if remaining < pause {
				pause = remaining
			}
			time.Sleep(pause)
		}
	}, func(p []byte) (int, error) {
		var available uint32
		r, _, callErr := peekNamedPipe.Call(uintptr(h), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
		if r == 0 {
			if callErr != windows.ERROR_SUCCESS {
				return 0, callErr
			}
			return 0, windows.ERROR_INVALID_HANDLE
		}
		if available == 0 {
			return 0, windows.ERROR_NO_DATA
		}
		if uint32(len(p)) > available {
			p = p[:available]
		}
		var read uint32
		if err := windows.ReadFile(h, p, &read, nil); err != nil {
			return 0, err
		}
		return int(read), nil
	})
}
