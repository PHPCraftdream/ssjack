package sshproxy

import (
	"encoding/binary"
	"io"
	"net"
)

func socksTunnel(conn net.Conn, address string, route *Config) error {
	method := byte(0)
	if route.Username != "" {
		method = 2
	}
	if err := writeAll(conn, []byte{5, 1, method}); err != nil {
		return err
	}
	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil || response != [2]byte{5, method} {
		return ErrProxy
	}
	if method == 2 {
		auth := make([]byte, 0, 3+len(route.Username)+len(route.Password))
		auth = append(auth, 1, byte(len(route.Username)))
		auth = append(auth, route.Username...)
		auth = append(auth, byte(len(route.Password)))
		auth = append(auth, route.Password...)
		err := writeAll(conn, auth)
		clear(auth)
		if err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, response[:]); err != nil || response != [2]byte{1, 0} {
			return ErrProxy
		}
	}
	host, port, err := endpoint(address)
	if err != nil {
		return err
	}
	request := []byte{5, 1, 0}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		request = append(request, 1)
		request = append(request, ip.To4()...)
	case ip != nil:
		request = append(request, 4)
		request = append(request, ip.To16()...)
	default:
		// Keep DNS at the proxy; never resolve the SSH hostname locally.
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, port)
	if err := writeAll(conn, request); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return ErrProxy
	}
	length := 0
	switch header[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil || size[0] == 0 {
			return ErrProxy
		}
		length = int(size[0])
	default:
		return ErrProxy
	}
	var bound [257]byte
	if _, err := io.ReadFull(conn, bound[:length+2]); err != nil {
		return ErrProxy
	}
	return nil
}
