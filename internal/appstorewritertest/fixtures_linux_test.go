//go:build linux

package appstorewritertest

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
	"os"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorhttp"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
)

type credentials struct {
	roots                  *x509.CertPool
	server, writer, reader tls.Certificate
	signer                 ed25519.PrivateKey
}

// Synthetic short-lived certificates follow the existing appstoreanchorhttp test fixture pattern.
func makeCredentials(t *testing.T) credentials {
	t.Helper()
	now := time.Now()
	seed := byte(71)
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	leaf := func(n byte, usage x509.ExtKeyUsage) tls.Certificate {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32))
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(n)), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, e := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{der, rootDER}, PrivateKey: key}
	}
	return credentials{roots: roots, server: leaf(72, x509.ExtKeyUsageServerAuth), writer: leaf(73, x509.ExtKeyUsageClientAuth), reader: leaf(74, x509.ExtKeyUsageClientAuth), signer: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{75}, 32))}
}

func storeID() [16]byte                       { return [16]byte{1} }
func credentialID(c tls.Certificate) [32]byte { return sha256.Sum256(c.Certificate[0]) }

func startService(t *testing.T, f credentials) (string, *appstoreanchortls.Writer, *appstoreanchorledger.Backend) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	backend, err := appstoreanchorledger.New(dir, storeID(), 16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://" + listener.Addr().String() + "/anchor"
	server, err := appstoreanchorhttp.New(appstoreanchorhttp.Config{Authority: listener.Addr().String(), Certificate: f.server, ClientCAs: f.roots, SigningKey: f.signer, Bindings: []appstoreanchorhttp.Binding{{CredentialID: credentialID(f.writer), StoreID: storeID(), Role: appstoreanchorcore.Writer, Backend: backend}, {CredentialID: credentialID(f.reader), StoreID: storeID(), Role: appstoreanchorcore.Reader, Backend: backend}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() { cancel(); _ = listener.Close(); _ = server.Close(); <-done })
	writer, err := appstoreanchortls.NewWriter(appstoreanchortls.Config{Endpoint: endpoint, RootCAs: f.roots, Certificate: f.writer, ServiceKey: f.signer.Public().(ed25519.PublicKey), StoreID: storeID()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	create, err := appstoreanchorrequest.NewCreate(storeID())
	if err != nil {
		t.Fatal(err)
	}
	ctxCreate, cancelCreate := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCreate()
	created, _, err := writer.Submit(ctxCreate, create)
	if err != nil || created.Outcome() != appstoreanchorreply.Committed {
		t.Fatalf("initialize anchor genesis: %v", err)
	}
	confirmed, err := writer.Read(ctxCreate)
	state, ok := confirmed.State()
	if err != nil || !ok || state.Sequence() != 0 {
		t.Fatalf("confirm genesis: %v", err)
	}
	return endpoint, writer, backend
}
