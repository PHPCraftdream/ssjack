// Package mcphttp owns private fixed-endpoint policy for future MCP connections.
package mcphttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrTransport = errors.New("remote MCP transport unavailable")

type endpointPolicy struct {
	endpoint, host, port string
}

func newEndpointPolicy(endpoint string) (*endpointPolicy, error) {
	if len(endpoint) == 0 || len(endpoint) > 2048 || strings.ContainsAny(endpoint, "\x00\r\n\t ") {
		return nil, ErrTransport
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(u.Path, "\x00\r\n") || strings.HasSuffix(u.Host, ":") || u.String() != endpoint {
		return nil, ErrTransport
	}
	host := u.Hostname()
	if address, err := netip.ParseAddr(host); err == nil {
		if !publicAddress(address) {
			return nil, ErrTransport
		}
	} else if !dnsName(host) {
		return nil, ErrTransport
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return nil, ErrTransport
	}
	return &endpointPolicy{endpoint: endpoint, host: host, port: port}, nil
}

func dnsName(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") || strings.ContainsAny(host, "%:\\/") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return true
}

func (p *endpointPolicy) requestAllowed(request *http.Request) bool {
	return p != nil && p.endpoint != "" && request != nil && request.URL != nil && request.URL.String() == p.endpoint && request.RequestURI == "" && (request.Host == "" || request.Host == request.URL.Host)
}

type lookupAddresses func(context.Context, string, string) ([]netip.Addr, error)
type dialAddress func(context.Context, string, string) (net.Conn, error)

func (p *endpointPolicy) dial(ctx context.Context, network, address string, lookup lookupAddresses, dial dialAddress) (net.Conn, error) {
	if p == nil || p.endpoint == "" || ctx == nil || ctx.Err() != nil || lookup == nil || dial == nil || (network != "tcp" && network != "tcp4" && network != "tcp6") {
		return nil, ErrTransport
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || !strings.EqualFold(host, p.host) || port != p.port {
		return nil, ErrTransport
	}
	addresses, err := lookup(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > 16 || ctx.Err() != nil {
		return nil, ErrTransport
	}
	for _, candidate := range addresses {
		if !publicAddress(candidate) {
			return nil, ErrTransport
		}
	}
	for _, candidate := range addresses {
		candidate = candidate.Unmap()
		if network == "tcp4" && !candidate.Is4() || network == "tcp6" && !candidate.Is6() {
			continue
		}
		connection, err := dial(ctx, network, net.JoinHostPort(candidate.String(), port))
		if err != nil {
			if connection != nil {
				connection.Close()
			}
			return nil, ErrTransport
		}
		if connection == nil {
			return nil, ErrTransport
		}
		return connection, nil
	}
	return nil, ErrTransport
}

func (p *endpointPolicy) transport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return p.dial(ctx, network, address, net.DefaultResolver.LookupNetIP, dialer.DialContext)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: p.host},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 4,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second,
	}
}

func rejectRedirect(*http.Request, []*http.Request) error { return ErrTransport }
