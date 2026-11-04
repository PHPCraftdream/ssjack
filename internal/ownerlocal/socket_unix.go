//go:build linux || darwin

package ownerlocal

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func normalize(path string) string { return path }
func endpointAddress(binding [32]byte) (string, error) {
	path := filepath.Join("/tmp", "ssjack-owner-"+hex.EncodeToString(binding[:16]), "control.sock")
	if len(path) >= 104 {
		return "", ErrEndpoint
	}
	return path, nil
}

func privateSocketDirectory(path string, create bool) error {
	if create {
		if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return ErrUnavailable
		}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return ErrAbsent
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink == 0 {
		return ErrUnavailable
	}
	return nil
}

type socketListener struct {
	listener *net.UnixListener
	identity os.FileInfo
	path     string
	once     sync.Once
	err      error
}

func listen(path string) (Listener, error) {
	if err := privateSocketDirectory(filepath.Dir(path), true); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, ErrBusy
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, ErrBusy
	}
	listener.SetUnlinkOnClose(false)
	owned := &socketListener{listener: listener, path: path}
	owned.identity, err = os.Lstat(path)
	if err != nil || os.Chmod(path, 0600) != nil {
		owned.Close()
		return nil, ErrUnavailable
	}
	return owned, nil
}

func (l *socketListener) Close() error {
	l.once.Do(func() {
		l.err = l.listener.Close()
		current, err := os.Lstat(l.path)
		if err == nil && l.identity != nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(l.identity, current) {
			if err := os.Remove(l.path); l.err == nil {
				l.err = err
			}
		}
	})
	return l.err
}

func (l *socketListener) Accept(ctx context.Context) (Connection, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrClosed
	}
	joined := make(chan struct{})
	deadline, _ := ctx.Deadline()
	if err := l.listener.SetDeadline(deadline); err != nil {
		return nil, ErrClosed
	}
	stop := context.AfterFunc(ctx, func() { _ = l.listener.SetDeadline(time.Now()); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	connection, err := l.listener.AcceptUnix()
	if err != nil {
		return nil, ErrClosed
	}
	if ctx.Err() != nil {
		connection.Close()
		return nil, ctx.Err()
	}
	return &socketConnection{connection: connection}, nil
}

func dial(ctx context.Context, path string) (Connection, error) {
	if err := privateSocketDirectory(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, ErrAbsent
	}
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return nil, ErrUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, ErrUnavailable
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, ErrUnavailable
	}
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, ErrUnavailable
	}
	return &socketConnection{connection: unix}, nil
}

type socketConnection struct {
	connection *net.UnixConn
	once       sync.Once
	err        error
}

func (c *socketConnection) Close() error {
	c.once.Do(func() { c.err = c.connection.Close() })
	return c.err
}
func (c *socketConnection) Read(ctx context.Context, data []byte) (int, error) {
	return c.transfer(ctx, data, true)
}
func (c *socketConnection) Write(ctx context.Context, data []byte) (int, error) {
	return c.transfer(ctx, data, false)
}
func (c *socketConnection) transfer(ctx context.Context, data []byte, read bool) (int, error) {
	if ctx == nil || ctx.Err() != nil {
		return 0, ErrClosed
	}
	deadline, _ := ctx.Deadline()
	set := c.connection.SetWriteDeadline
	if read {
		set = c.connection.SetReadDeadline
	}
	if err := set(deadline); err != nil {
		return 0, ErrClosed
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.Close(); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
		_ = set(time.Time{})
	}()
	var n int
	var err error
	if read {
		n, err = c.connection.Read(data)
	} else {
		n, err = c.connection.Write(data)
	}
	if ctx.Err() != nil {
		return n, ctx.Err()
	}
	if errors.Is(err, net.ErrClosed) {
		return n, ErrClosed
	}
	return n, err
}
