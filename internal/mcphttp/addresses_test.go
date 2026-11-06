package mcphttp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestPublicAddressPolicyUnmapsAndRefusesSpecialNetworks(t *testing.T) {
	for _, value := range []string{"1.1.1.1", "8.8.8.8", "100.128.0.1", "198.20.0.1", "2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450::1", "::ffff:8.8.8.8"} {
		if !publicAddress(netip.MustParseAddr(value)) {
			t.Fatal("ordinary public address was refused")
		}
	}
	for _, value := range []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "127.0.0.1", "127.255.255.254", "169.254.169.254", "172.16.0.1", "192.168.1.1",
		"100.64.0.1", "100.100.100.200", "100.127.255.254", "192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.19.255.254", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::192.168.1.1", "fc00::1", "fd00:ec2::254", "fe80::1", "ff02::1",
		"64:ff9b::a00:1", "64:ff9b:1::1", "100::1", "2001::1", "2001:10::1", "2001:db8::1", "2002:7f00:1::1", "3ffe::1", "3fff::1", "5f00::1", "2606:4700:4700::1111%zone",
	} {
		if publicAddress(netip.MustParseAddr(value)) {
			t.Fatal("non-public or special address was admitted")
		}
	}
	if publicAddress(netip.Addr{}) {
		t.Fatal("invalid address was admitted")
	}
}

func TestDialRefusesCancellationWrongNetworkAndPrivateDialDiagnostics(t *testing.T) {
	policy, err := newEndpointPolicy("https://mcp.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("synthetic private dial diagnostic")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		if _, err := policy.dial(ctx, "tcp", "mcp.example.org:443", lookup, dial); err != ErrTransport || calls != 0 {
			t.Fatal("invalid context reached DNS or dial")
		}
	}
	if _, err := policy.dial(context.Background(), "udp", "mcp.example.org:443", lookup, dial); err != ErrTransport || calls != 0 {
		t.Fatal("unsupported network reached DNS or dial")
	}
	if _, err := policy.dial(context.Background(), "tcp", "mcp.example.org:443", lookup, dial); err != ErrTransport || calls != 2 {
		t.Fatal("dial failure was replayed or exposed private diagnostics")
	}
	if _, err := policy.dial(context.Background(), "tcp6", "mcp.example.org:443", lookup, dial); err != ErrTransport || calls != 3 {
		t.Fatal("wrong address family reached dial")
	}
	if _, err := policy.dial(context.Background(), "tcp", "mcp.example.org:443", lookup, func(context.Context, string, string) (net.Conn, error) { return nil, nil }); err != ErrTransport {
		t.Fatal("nil connection was reported as a successful dial")
	}
}
