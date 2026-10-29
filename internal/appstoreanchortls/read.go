package appstoreanchortls

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
)

// Read creates one fresh correlated Read; it never retries or sends mutations.
func (c *Client) Read(ctx context.Context) (appstoreanchorreply.Reply, error) {
	if ctx == nil {
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) {
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return appstoreanchorreply.Reply{}, err
	}
	if c == nil || c.state == nil {
		return appstoreanchorreply.Reply{}, ErrClosed
	}
	s := c.state
	if !s.mu.TryLock() {
		return appstoreanchorreply.Reply{}, ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed || len(s.privateDER) == 0 {
		return appstoreanchorreply.Reply{}, ErrClosed
	}
	private, err := x509.ParsePKCS8PrivateKey(s.privateDER)
	if err != nil {
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	certificate := tls.Certificate{Certificate: s.chain, PrivateKey: private}
	var requestID [16]byte
	if _, err := rand.Read(requestID[:]); err != nil || requestID == ([16]byte{}) {
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	request, err := appstoreanchorrequest.NewRead(s.store, requestID)
	if err != nil {
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	var dialed atomic.Bool
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: 1, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 4096}
	transport.DialTLSContext = func(_ context.Context, network, address string) (net.Conn, error) {
		if !dialed.CompareAndSwap(false, true) || !strings.EqualFold(address, s.address) {
			return nil, ErrUnavailable
		}
		var requested atomic.Bool
		config := &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: s.host,
			RootCAs: s.roots.Clone(), SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"},
			GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if err := info.SupportsCertificate(&certificate); err != nil {
					return nil, ErrUnavailable
				}
				requested.Store(true)
				return &certificate, nil
			},
		}
		raw, err := (&net.Dialer{Deadline: deadline}).DialContext(ctx, network, address)
		if err != nil {
			return nil, ErrUnavailable
		}
		if err := raw.SetDeadline(deadline); err != nil {
			raw.Close()
			return nil, ErrUnavailable
		}
		conn := tls.Client(raw, config)
		if err := conn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, ErrUnavailable
		}
		state := conn.ConnectionState()
		if !requested.Load() || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || state.DidResume {
			conn.Close()
			return nil, ErrUnavailable
		}
		return conn, nil
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(request.Bytes()))
	if err != nil {
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	httpRequest.Header.Set("Content-Type", "application/octet-stream")
	httpRequest.Header.Set("Accept", "application/octet-stream")
	response, err := client.Do(httpRequest)
	if err != nil {
		if ctx.Err() != nil {
			return appstoreanchorreply.Reply{}, ctx.Err()
		}
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || len(response.TLS.VerifiedChains) == 0 {
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 353))
	defer clear(body)
	if err != nil || len(body) != 352 {
		if ctx.Err() != nil {
			return appstoreanchorreply.Reply{}, ctx.Err()
		}
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	reply, err := appstoreanchorreply.Verify(body, s.signer[:], appstoreanchorreply.Expected{Operation: appstoreanchorreply.Read, RequestID: requestID, StoreID: s.store})
	if err != nil {
		return appstoreanchorreply.Reply{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return appstoreanchorreply.Reply{}, err
	}
	return reply, nil
}
