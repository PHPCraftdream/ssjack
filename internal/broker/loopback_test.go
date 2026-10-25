package broker

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestRejectNoncanonicalEndpointsBeforeTLSOrDial(t *testing.T) {
	for _, endpoint := range []string{
		"192.0.2.1:443", "0.0.0.0:1234", "localhost:1234", "127.0.0.1.example:1234",
		"[::1]:1234", "[::ffff:127.0.0.1]:1234", "[::]:1234", "2130706433:1234",
		"127.0.0.1:http", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:+22", "127.0.0.1",
	} {
		if _, err := Connect(context.Background(), endpoint, "invalid pin", wire.Auth{}); err == nil || !strings.Contains(err.Error(), "keeper endpoint") {
			t.Fatalf("endpoint reached TLS validation or dial: %q: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"127.0.0.1:1", "127.0.0.1:65535"} {
		if err := validateEndpoint(endpoint); err != nil {
			t.Fatalf("valid endpoint rejected: %q: %v", endpoint, err)
		}
	}
}

func TestOnlyTCPRemoteLoopbackPeersAreAccepted(t *testing.T) {
	for _, address := range []net.Addr{nil, (*net.TCPAddr)(nil), &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}, &net.TCPAddr{IP: net.IPv4zero}} {
		if loopbackPeer(address) {
			t.Fatalf("non-loopback TCP peer accepted: %v", address)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if !loopbackPeer(&net.TCPAddr{IP: net.ParseIP(ip), Port: 12345}) {
			t.Fatalf("loopback peer rejected: %s", ip)
		}
	}
}
