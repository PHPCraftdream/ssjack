package sshproxy

import (
	"context"
	"io"
	"net"
	"time"
)

const handshakeTimeout = 10 * time.Second

// DialContext never consults HTTP_PROXY/ALL_PROXY and never falls back to direct.
func DialContext(ctx context.Context, address string, route *Config) (net.Conn, error) {
	if ctx == nil {
		return nil, ErrConfig
	}
	if route == nil {
		dialer := net.Dialer{Timeout: handshakeTimeout}
		return dialer.DialContext(ctx, "tcp", address)
	}
	if route.Type == "" || route.Validate() != nil {
		return nil, ErrConfig
	}
	if _, _, err := endpoint(address); err != nil {
		return nil, ErrConfig
	}
	route = Clone(route)
	defer route.Clear()
	op, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(op, "tcp", route.Address)
	if err != nil {
		return nil, tunnelError(op)
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(op, func() { defer close(stopped); conn.Close() })
	success := false
	defer func() {
		if !stop() {
			<-stopped
		}
		if !success {
			conn.Close()
		}
	}()
	deadline, _ := op.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, ErrProxy
	}
	var tunneled net.Conn = conn
	switch route.Type {
	case SOCKS5:
		err = socksTunnel(conn, address, route)
	case HTTP:
		tunneled, err = httpTunnel(conn, address, route)
	default:
		err = ErrConfig
	}
	if err != nil || op.Err() != nil {
		return nil, tunnelError(op)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, ErrProxy
	}
	success = true
	return tunneled, nil
}

func tunnelError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return ErrProxy
}

func writeAll(output io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := output.Write(data)
		if n < 0 || n > len(data) {
			return ErrProxy
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
