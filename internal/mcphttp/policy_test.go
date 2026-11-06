package mcphttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
)

func TestFixedHTTPSPolicyRejectsRoutingAndRequestSubstitution(t *testing.T) {
	for _, endpoint := range []string{"https://mcp.example.org/mcp", "https://8.8.8.8:8443/mcp", "https://[2606:4700:4700::1111]/mcp"} {
		policy, err := newEndpointPolicy(endpoint)
		if err != nil {
			t.Fatal("valid fixed public endpoint was refused")
		}
		request, err := http.NewRequest(http.MethodPost, endpoint, nil)
		if err != nil || !policy.requestAllowed(request) {
			t.Fatal("exact request was refused")
		}
		request.Host = "other.example.org"
		if policy.requestAllowed(request) {
			t.Fatal("Host override escaped the fixed endpoint")
		}
		request.Host = ""
		request.URL.Path += "/other"
		if policy.requestAllowed(request) || policy.requestAllowed(nil) {
			t.Fatal("path substitution or nil request was accepted")
		}
	}
	for _, endpoint := range []string{
		"", "http://mcp.example.org/mcp", "https://user:password@mcp.example.org/mcp",
		"https://mcp.example.org/mcp?token=value", "https://mcp.example.org/mcp?", "https://mcp.example.org/mcp#fragment", "https://mcp.example.org/mcp#",
		"https://mcp.example.org:/mcp", "https://mcp.example.org:0443/mcp", "https://mcp.example.org:65536/mcp",
		"https://localhost/mcp", "https://bad_host.example.org/mcp", "https://mcp.example.org/%00",
		"https://127.0.0.1/mcp", "https://169.254.169.254/mcp", "https://100.100.100.200/mcp", "https://[::ffff:127.0.0.1]/mcp", "https://[fe80::1%25zone]/mcp",
	} {
		if policy, err := newEndpointPolicy(endpoint); policy != nil || err != ErrTransport {
			t.Fatal("unsafe endpoint was accepted or exposed private diagnostics")
		}
	}
}

func TestDialValidatesAllAnswersAndUsesResolvedLiteralWithoutSecondLookup(t *testing.T) {
	policy, err := newEndpointPolicy("https://mcp.example.org:8443/mcp")
	if err != nil {
		t.Fatal(err)
	}
	lookups, dials := 0, 0
	lookup := func(_ context.Context, network, host string) ([]netip.Addr, error) {
		lookups++
		if network != "ip" || host != "mcp.example.org" {
			t.Fatal("dial changed DNS scope")
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		dials++
		if network != "tcp" || address != "8.8.8.8:8443" {
			t.Fatal("dial used a hostname, proxy or unapproved port")
		}
		client, peer := net.Pipe()
		peer.Close()
		return client, nil
	}
	connection, err := policy.dial(context.Background(), "tcp", "mcp.example.org:8443", lookup, dial)
	if err != nil || lookups != 1 || dials != 1 {
		t.Fatal("dial repeated resolution or changed a successful result")
	}
	connection.Close()
	for _, answers := range [][]netip.Addr{
		nil, {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("::ffff:169.254.169.254")},
		make([]netip.Addr, 17),
	} {
		_, err := policy.dial(context.Background(), "tcp", "mcp.example.org:8443", func(context.Context, string, string) ([]netip.Addr, error) { return answers, nil }, dial)
		if err != ErrTransport || dials != 1 {
			t.Fatal("unsafe or excessive answers were skipped or truncated before dialing")
		}
	}
	for _, address := range []string{"other.example.org:8443", "mcp.example.org:443", "malformed"} {
		if _, err := policy.dial(context.Background(), "tcp", address, lookup, dial); err != ErrTransport || lookups != 1 || dials != 1 {
			t.Fatal("substituted address reached DNS or dial")
		}
	}
	private := errors.New("synthetic private DNS diagnostic")
	if _, err := policy.dial(context.Background(), "tcp", "mcp.example.org:8443", func(context.Context, string, string) ([]netip.Addr, error) { return nil, private }, dial); err != ErrTransport || dials != 1 {
		t.Fatal("lookup failure exposed private diagnostics or reached dial")
	}
}

func TestTransportDisablesEnvironmentProxyAndBoundsTLSAndHeaders(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	policy, err := newEndpointPolicy("https://mcp.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	transport := policy.transport()
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || transport.TLSClientConfig.ServerName != "mcp.example.org" || transport.DialContext == nil || transport.MaxResponseHeaderBytes != 16<<10 || transport.MaxConnsPerHost != 4 || !transport.DisableCompression || transport.TLSHandshakeTimeout <= 0 || transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("HTTP policy lost route, TLS or resource bounds")
	}
	if rejectRedirect(nil, nil) != ErrTransport {
		t.Fatal("redirect policy permitted endpoint adoption")
	}
}
