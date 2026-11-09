package ownerlocal

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"

	"golang.org/x/sys/windows"
)

// Win32 CreateNamedPipe byte mode, duplex access, and local clients only.
const pipeDuplex, pipeRejectRemote = 0x00000003, 0x00000008
const maxPipeInstances = 32

func normalize(path string) string {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(handle, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return ""
	}
	buffer := make([]uint16, 512)
	// VOLUME_NAME_GUID also normalizes drive aliases and short filenames.
	count, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 1)
	if err != nil || count == 0 || count > 32768 {
		return ""
	}
	if count >= uint32(len(buffer)) {
		buffer = make([]uint16, int(count)+1)
		count, err = windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 1)
		if err != nil || count == 0 || count >= uint32(len(buffer)) {
			return ""
		}
	}
	return windows.UTF16ToString(buffer[:count])
}
func endpointAddress(binding [32]byte) (string, error) {
	return `\\.\pipe\ssjack-owner-` + hex.EncodeToString(binding[:]), nil
}

func pipeDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, ErrUnavailable
	}
	sid := user.User.Sid.String()
	if sid == "" {
		return nil, ErrUnavailable
	}
	return windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;GA;;;" + sid + ")")
}

func createPipe(path string, first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, ErrEndpoint
	}
	descriptor, err := pipeDescriptor()
	if err != nil {
		return windows.InvalidHandle, ErrUnavailable
	}
	attributes := windows.SecurityAttributes{Length: uint32(reflect.TypeOf(windows.SecurityAttributes{}).Size()), SecurityDescriptor: descriptor}
	mode := uint32(pipeDuplex | windows.FILE_FLAG_OVERLAPPED)
	if first {
		mode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	handle, err := windows.CreateNamedPipe(name, mode, pipeRejectRemote, maxPipeInstances, 65536, 65536, 1000, &attributes)
	if err != nil {
		return windows.InvalidHandle, ErrBusy
	}
	return handle, nil
}

type pipeListener struct {
	path   string
	handle windows.Handle
	claim  windows.Handle
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	accept sync.Mutex
	active sync.WaitGroup
	closed bool
	once   sync.Once
	err    error
}

func listen(path string) (Listener, error) {
	descriptor, err := pipeDescriptor()
	if err != nil {
		return nil, ErrUnavailable
	}
	claimName, err := windows.UTF16PtrFromString(`Global\ssjack-owner-claim-` + hex.EncodeToString([]byte(path)))
	if err != nil {
		return nil, ErrEndpoint
	}
	attributes := windows.SecurityAttributes{Length: uint32(reflect.TypeOf(windows.SecurityAttributes{}).Size()), SecurityDescriptor: descriptor}
	claim, err := windows.CreateEvent(&attributes, 1, 0, claimName)
	if err != nil {
		if claim != 0 && claim != windows.InvalidHandle {
			windows.CloseHandle(claim)
		}
		return nil, ErrBusy
	}
	handle, err := createPipe(path, true)
	if err != nil {
		windows.CloseHandle(claim)
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &pipeListener{path: path, handle: handle, claim: claim, ctx: ctx, cancel: cancel}, nil
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.cancel()
		if l.handle != windows.InvalidHandle {
			_ = windows.CancelIoEx(l.handle, nil)
		}
		l.mu.Unlock()
		l.active.Wait()
		l.mu.Lock()
		if l.handle != windows.InvalidHandle {
			l.err = windows.CloseHandle(l.handle)
			l.handle = windows.InvalidHandle
		}
		if err := windows.CloseHandle(l.claim); l.err == nil {
			l.err = err
		}
		l.mu.Unlock()
	})
	return l.err
}

func (l *pipeListener) Accept(caller context.Context) (Connection, error) {
	if caller == nil || caller.Err() != nil {
		return nil, ErrClosed
	}
	l.accept.Lock()
	defer l.accept.Unlock()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	if l.handle == windows.InvalidHandle {
		l.mu.Unlock()
		return nil, ErrUnavailable
	}
	handle := l.handle
	l.active.Add(1)
	l.mu.Unlock()
	defer l.active.Done()
	ctx, done := mergeLifetime(l.ctx, caller)
	defer done()
	_, err := overlapped(ctx, handle, nil, func(overlap *windows.Overlapped, _ *uint32) error {
		err := windows.ConnectNamedPipe(handle, overlap)
		if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			return nil
		}
		return err
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, ErrClosed
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	// Pin a successor before handing off or closing the current instance.
	next, createError := createPipe(l.path, false)
	if createError != nil {
		l.closed = true
		l.cancel()
		return nil, createError
	}
	l.handle = next
	if err != nil {
		if closeError := windows.CloseHandle(handle); closeError != nil {
			l.closed = true
			l.cancel()
		}
		return nil, ErrUnavailable
	}
	return newPipeConnection(handle), nil
}

func dial(ctx context.Context, path string) (Connection, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrEndpoint
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, ErrAbsent
	}
	if errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return nil, ErrBusy
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	if ctx.Err() != nil {
		windows.CloseHandle(handle)
		return nil, ctx.Err()
	}
	return newPipeConnection(handle), nil
}
