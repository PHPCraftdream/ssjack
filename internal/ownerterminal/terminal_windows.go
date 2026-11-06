package ownerterminal

import (
	"context"
	"os"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

func start(ctx context.Context, spec Command) (_ *Terminal, result error) {
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return nil, ErrTerminal
	}
	defer inRead.Close()
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		_ = inWrite.Close()
		return nil, ErrTerminal
	}
	defer outWrite.Close()
	var console windows.Handle
	if err = windows.CreatePseudoConsole(windows.Coord{X: 200, Y: 60}, windows.Handle(inRead.Fd()), windows.Handle(outWrite.Fd()), 0, &console); err != nil {
		_ = inWrite.Close()
		_ = outRead.Close()
		return nil, ErrTerminal
	}
	defer func() {
		if result != nil {
			_ = inWrite.Close()
			_ = outRead.Close()
			windows.ClosePseudoConsole(console)
		}
	}()
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, ErrTerminal
	}
	defer attributes.Delete()
	// The attribute takes the native HPCON value, not a pointer to a Go handle.
	if err = attributes.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(console), unsafe.Sizeof(console)); err != nil {
		return nil, ErrTerminal
	}
	application, err := windows.UTF16PtrFromString(spec.Executable)
	if err != nil {
		return nil, ErrTerminal
	}
	arguments := append([]string{spec.Executable}, spec.Args...)
	command, err := windows.UTF16FromString(windows.ComposeCommandLine(arguments))
	if err != nil {
		return nil, ErrTerminal
	}
	var directory *uint16
	if spec.Directory != "" {
		directory, err = windows.UTF16PtrFromString(spec.Directory)
		if err != nil {
			return nil, ErrTerminal
		}
	}
	entries := append([]string(nil), spec.Environment...)
	sort.SliceStable(entries, func(i, j int) bool { return strings.ToUpper(entries[i]) < strings.ToUpper(entries[j]) })
	environment := make([]uint16, 0)
	for _, entry := range entries {
		encoded, encodeErr := windows.UTF16FromString(entry)
		if encodeErr != nil {
			return nil, ErrTerminal
		}
		environment = append(environment, encoded...)
	}
	environment = append(environment, 0)
	if len(environment) == 1 {
		environment = append(environment, 0)
	}
	startup := windows.StartupInfoEx{ProcThreadAttributeList: attributes.List()}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	var process windows.ProcessInformation
	if err = windows.CreateProcess(application, &command[0], nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		&environment[0], directory, &startup.StartupInfo, &process); err != nil {
		return nil, ErrTerminal
	}
	_ = windows.CloseHandle(process.Thread)
	t := &Terminal{Input: inWrite, Output: outRead, done: make(chan struct{}), watch: make(chan struct{})}
	var processMu sync.Mutex
	t.stop = func() {
		processMu.Lock()
		defer processMu.Unlock()
		select {
		case <-t.done:
		default:
			_ = windows.TerminateProcess(process.Process, 1)
		}
	}
	go func() {
		_, waitErr := windows.WaitForSingleObject(process.Process, windows.INFINITE)
		var code uint32
		if waitErr != nil || windows.GetExitCodeProcess(process.Process, &code) != nil || code != 0 {
			t.err = ErrTerminal
		}
		windows.ClosePseudoConsole(console)
		processMu.Lock()
		close(t.done)
		_ = windows.CloseHandle(process.Process)
		processMu.Unlock()
	}()
	t.observe(ctx)
	return t, nil
}
