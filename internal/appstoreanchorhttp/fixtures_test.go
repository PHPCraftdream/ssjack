package appstoreanchorhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
)

type certificates struct {
	roots                           *x509.CertPool
	root                            *x509.Certificate
	server, writer, reader, unknown tls.Certificate
	signer                          ed25519.PrivateKey
}

func certs(t *testing.T, seed byte) certificates {
	t.Helper()
	now := time.Now()
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	leaf := func(n byte, usage x509.ExtKeyUsage) tls.Certificate {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32))
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(n)), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		raw, err := x509.CreateCertificate(rand.Reader, cert, root, key.Public(), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{raw, der}, PrivateKey: key}
	}
	return certificates{roots: roots, root: root, server: leaf(seed+1, x509.ExtKeyUsageServerAuth), writer: leaf(seed+2, x509.ExtKeyUsageClientAuth), reader: leaf(seed+3, x509.ExtKeyUsageClientAuth), unknown: leaf(seed+4, x509.ExtKeyUsageClientAuth), signer: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 5}, 32))}
}
func storeID() [16]byte                         { return [16]byte{1} }
func fingerprint(cert tls.Certificate) [32]byte { return sha256.Sum256(cert.Certificate[0]) }
func backend(t *testing.T) (*appstoreanchorledger.Backend, *os.File) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux durable backend required")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	b, err := appstoreanchorledger.New(dir, storeID(), 16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b, dir
}
func configuration(authority string, f certificates, b *appstoreanchorledger.Backend) Config {
	return Config{Authority: authority, Certificate: f.server, ClientCAs: f.roots, SigningKey: f.signer, Bindings: []Binding{
		{CredentialID: fingerprint(f.writer), StoreID: storeID(), Role: appstoreanchorcore.Writer, Backend: b},
		{CredentialID: fingerprint(f.reader), StoreID: storeID(), Role: appstoreanchorcore.Reader, Backend: b},
	}}
}
func start(t *testing.T, config Config) (*Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.Authority = listener.Addr().String()
	s, err := New(config)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, listener) }()
	t.Cleanup(func() { cancel(); listener.Close(); s.Close(); <-done })
	return s, "https://" + listener.Addr().String() + "/anchor"
}
func transport(f certificates, certificate tls.Certificate) *http.Transport {
	return &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: f.roots, Certificates: []tls.Certificate{certificate}, SessionTicketsDisabled: true}}
}
func deadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
