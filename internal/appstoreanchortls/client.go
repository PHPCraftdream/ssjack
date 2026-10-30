// Package appstoreanchortls provides separate fixed-scope read and writer HTTPS/mTLS bindings.
package appstoreanchortls

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

var ErrInvalid = errors.New("invalid application-store anchor TLS configuration")
var ErrUnavailable = errors.New("application-store anchor TLS read unavailable")
var ErrBusy = errors.New("application-store anchor TLS client busy")
var ErrClosed = errors.New("application-store anchor TLS client closed")

type Config struct {
	Endpoint    string
	RootCAs     *x509.CertPool
	Certificate tls.Certificate
	ServiceKey  ed25519.PublicKey
	StoreID     [16]byte
}

type clientState struct {
	mu         sync.Mutex
	endpoint   string
	host       string
	address    string
	roots      *x509.CertPool
	chain      [][]byte
	privateDER []byte
	signer     [32]byte
	store      [16]byte
	closed     bool
}

type Client struct{ state *clientState }

// New selects no defaults and reads no credential files. Supplied trust is not enrollment.
func New(config Config) (*Client, error) {
	u, err := url.Parse(config.Endpoint)
	if err != nil || len(config.Endpoint) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(config.Endpoint, "#") || u.Opaque != "" {
		return nil, ErrInvalid
	}
	host := u.Hostname()
	if len(host) > 253 || strings.ContainsAny(host, "%\r\n") {
		return nil, ErrInvalid
	}
	for _, b := range []byte(host) {
		if b > 127 {
			return nil, ErrInvalid
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 || config.RootCAs == nil || len(config.RootCAs.Subjects()) == 0 || config.StoreID == ([16]byte{}) || len(config.ServiceKey) != 32 || zero(config.ServiceKey) {
		return nil, ErrInvalid
	}
	cert := config.Certificate
	if len(cert.Certificate) == 0 || len(cert.Certificate) > 8 || cert.PrivateKey == nil {
		return nil, ErrInvalid
	}
	var chain [][]byte
	total := 0
	for _, der := range cert.Certificate {
		total += len(der)
		if len(der) == 0 || len(der) > 16384 || total > 65536 {
			return nil, ErrInvalid
		}
		chain = append(chain, append([]byte(nil), der...))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, ErrInvalid
	}
	private, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(private)
	if len(private) == 0 || len(private) > 32768 {
		return nil, ErrInvalid
	}
	owned, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		return nil, ErrInvalid
	}
	signer, ok := owned.(crypto.Signer)
	if !ok {
		return nil, ErrInvalid
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, ErrInvalid
	}
	leafPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(public, leafPublic) {
		return nil, ErrInvalid
	}
	s := &clientState{endpoint: u.String(), host: host, address: net.JoinHostPort(host, port), roots: config.RootCAs.Clone(), chain: chain, privateDER: append([]byte(nil), private...), store: config.StoreID}
	copy(s.signer[:], config.ServiceKey)
	return &Client{state: s}, nil
}

func zero(b []byte) bool {
	var value byte
	for _, v := range b {
		value |= v
	}
	return value == 0
}

func (c *Client) Close() error {
	if c == nil || c.state == nil {
		return nil
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	clear(c.state.privateDER)
	c.state.privateDER = nil
	c.state.closed = true
	return nil
}
