package nativeownercheck

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

// The test authority is volatile. It tests native clients, not durable service storage.
func authority(t *testing.T, header appstoreheader.Header, dev, ino uint64) appstorecrypto.Binding {
	t.Helper()
	now := time.Now()
	caKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	must(t, err)
	ca, err := x509.ParseCertificate(caDER)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(seed byte, usage x509.ExtKeyUsage) tls.Certificate {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(seed)), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		must(t, err)
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	serverCert, clientCert := leaf(92, x509.ExtKeyUsageServerAuth), leaf(93, x509.ExtKeyUsageClientAuth)
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{94}, 32))
	credential := sha256.Sum256(clientCert.Certificate[0])
	grant, err := appstoreanchorcore.NewGrant(header.StoreID(), credential, appstoreanchorcore.Writer)
	must(t, err)
	current, err := appstoreanchorcore.Missing(header.StoreID())
	must(t, err)
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/anchor" || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || sha256.Sum256(r.TLS.PeerCertificates[0].Raw) != credential || r.Header.Get("Content-Type") != "application/octet-stream" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 305))
		if err != nil || len(raw) > 304 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		request, err := appstoreanchorcore.Parse(raw, header.StoreID())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		result, err := appstoreanchorcore.Evaluate(request, grant, current)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		unsigned, err := result.Unsigned()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if next, ok := result.Next(); ok {
			current = next
		}
		signature := ed25519.Sign(signer, unsigned[:])
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(append(unsigned[:], signature...))
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientCert.PrivateKey)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(); clear(privateDER); clear(signer) })
	return appstorecrypto.Binding{Endpoint: server.URL + "/anchor", RootsDER: [][]byte{caDER}, CertificateDER: clientCert.Certificate, PrivateDER: privateDER, ServiceKey: signer.Public().(ed25519.PublicKey), Header: header, DirectoryDev: dev, DirectoryIno: ino}
}
