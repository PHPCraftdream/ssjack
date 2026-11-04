package sshproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
)

const maxHTTPHeader = 16 * 1024

type bufferedConn struct {
	net.Conn
	input *bufio.Reader
}

func (c *bufferedConn) Read(data []byte) (int, error) { return c.input.Read(data) }

func httpTunnel(conn net.Conn, address string, route *Config) (net.Conn, error) {
	request := []byte("CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n")
	if route.Username != "" {
		credential := append([]byte(route.Username+":"), route.Password...)
		authorization := make([]byte, base64.StdEncoding.EncodedLen(len(credential)))
		base64.StdEncoding.Encode(authorization, credential)
		clear(credential)
		request = append(request, "Proxy-Authorization: Basic "...)
		request = append(request, authorization...)
		request = append(request, '\r', '\n')
		clear(authorization)
	}
	request = append(request, '\r', '\n')
	err := writeAll(conn, request)
	clear(request)
	if err != nil {
		return nil, ErrProxy
	}
	input := bufio.NewReaderSize(conn, maxHTTPHeader)
	header := make([]byte, 0, maxHTTPHeader)
	defer func() { clear(header) }()
	for {
		line, err := input.ReadSlice('\n')
		if err != nil || len(header)+len(line) > maxHTTPHeader || !bytes.HasSuffix(line, []byte("\r\n")) {
			return nil, ErrProxy
		}
		header = append(header, line...)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	// Parse only the bounded header, not the tunnel or any untrusted body.
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, ErrProxy
	}
	response.Body.Close()
	if response.ProtoMajor != 1 || response.ProtoMinor > 1 || response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, ErrProxy
	}
	// Preserve an SSH banner that arrived in the same read as the CONNECT reply.
	return &bufferedConn{Conn: conn, input: input}, nil
}
