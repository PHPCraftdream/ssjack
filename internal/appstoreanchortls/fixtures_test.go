package appstoreanchortls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fixtures struct {
	roots  *x509.CertPool
	server tls.Certificate
	client tls.Certificate
	signer ed25519.PrivateKey
}

func fixture(t *testing.T, seed byte) fixtures {
	t.Helper()
	now := time.Now()
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic anchor CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	leaf := func(n byte, usage x509.ExtKeyUsage) tls.Certificate {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32))
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(n)), Subject: pkix.Name{CommonName: "synthetic anchor peer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, cert, rootCert, key.Public(), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, rootDER}, PrivateKey: key}
	}
	return fixtures{roots: roots, server: leaf(seed+1, x509.ExtKeyUsageServerAuth), client: leaf(seed+2, x509.ExtKeyUsageClientAuth), signer: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 3}, 32))}
}

func server(t *testing.T, f fixtures, auth tls.ClientAuthType, version uint16, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{f.server}, ClientAuth: auth, ClientCAs: f.roots, MinVersion: version, MaxVersion: version, NextProtos: []string{"http/1.1"}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func config(endpoint string, f fixtures) Config {
	return Config{Endpoint: endpoint, RootCAs: f.roots, Certificate: f.client, ServiceKey: f.signer.Public().(ed25519.PublicKey), StoreID: [16]byte(bytes.Repeat([]byte{1}, 16))}
}

func signedReply(t *testing.T, request []byte, signer ed25519.PrivateKey) []byte {
	t.Helper()
	if len(request) != 48 || string(request[:8]) != "SSASREQ1" || request[8] != 1 || !zero(request[9:16]) || zero(request[16:32]) || zero(request[32:48]) {
		t.Error("client sent noncanonical/non-Read request")
		return nil
	}
	state := make([]byte, 192)
	copy(state[:4], "SSAS")
	binary.BigEndian.PutUint16(state[4:6], 1)
	copy(state[8:24], request[16:32])
	head := sha256.Sum256(append([]byte("SSAPP-JOURNAL-GENESIS-v1"), request[16:32]...))
	copy(state[104:136], head[:])
	stateHash := sha256.Sum256(append([]byte("SSAPP-ANCHOR-STATE-v1"), state...))
	b := make([]byte, 352)
	copy(b[:8], "SSASRSP1")
	b[8], b[9] = 1, 1
	copy(b[16:32], request[32:48])
	copy(b[32:48], request[16:32])
	binary.BigEndian.PutUint16(b[56:58], 192)
	copy(b[64:256], state)
	copy(b[256:288], stateHash[:])
	copy(b[288:352], ed25519.Sign(signer, b[:288]))
	return b
}
