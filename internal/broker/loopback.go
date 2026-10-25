package broker

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

func validateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host != "127.0.0.1" || strings.Trim(port, "0123456789") != "" {
		return errors.New("keeper endpoint must use literal 127.0.0.1 and a numeric TCP port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("keeper endpoint port must be between 1 and 65535")
	}
	return nil
}

func loopbackPeer(address net.Addr) bool {
	peer, ok := address.(*net.TCPAddr)
	return ok && peer != nil && peer.IP.IsLoopback()
}
