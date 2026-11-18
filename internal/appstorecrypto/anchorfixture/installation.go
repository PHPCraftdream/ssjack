package anchorfixture

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
	"runtime"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorhttp"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

// BindingParts mirrors masterkey.Binding field for field; convert with masterkey.Binding(parts).
type BindingParts struct {
	Endpoint       string
	RootsDER       [][]byte
	CertificateDER [][]byte
	PrivateDER     []byte
	ServiceKey     []byte
	Header         appstoreheader.Header
	DirectoryDev   uint64
	DirectoryIno   uint64
}

// TestBinding returns a syntactically valid binding and its header.
func TestBinding(t *testing.T) (appstoreheader.Header, BindingParts) {
	t.Helper()
	h := Header(t)
	now := time.Now()
	caKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return h, BindingParts{Endpoint: "https://localhost/anchor", RootsDER: [][]byte{caDER}, CertificateDER: [][]byte{leafDER, caDER}, PrivateDER: privateDER, ServiceKey: bytes.Repeat([]byte{3}, 32), Header: h, DirectoryDev: 1, DirectoryIno: 2}
}

// InstallationAnchor builds a store directory, entry store and live anchor for an installation.
func InstallationAnchor(t *testing.T) (*appstorefile.Directory, *appstoreentry.Store, BindingParts) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux durable service required")
	}
	h := Header(t)
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := appstoreentry.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dev, ino, err := store.Identity()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := appstorefile.Open(root, h.StoreID())
	_ = root.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })

	ledgerPath := t.TempDir()
	if err = os.Chmod(ledgerPath, 0700); err != nil {
		t.Fatal(err)
	}
	ledgerRoot, err := os.Open(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := appstoreanchorledger.New(ledgerRoot, h.StoreID(), 64)
	_ = ledgerRoot.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	now := time.Now()
	caKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(seed byte, usage x509.ExtKeyUsage) tls.Certificate {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(seed)), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	serverCert, writerCert := leaf(72, x509.ExtKeyUsageServerAuth), leaf(73, x509.ExtKeyUsageClientAuth)
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{75}, 32))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service, err := appstoreanchorhttp.New(appstoreanchorhttp.Config{Authority: listener.Addr().String(), Certificate: serverCert, ClientCAs: roots, SigningKey: signer, Bindings: []appstoreanchorhttp.Binding{{CredentialID: sha256.Sum256(writerCert.Certificate[0]), StoreID: h.StoreID(), Role: appstoreanchorcore.Writer, Backend: backend}}})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, listener) }()
	t.Cleanup(func() { cancel(); _ = listener.Close(); _ = service.Close(); <-done })
	endpoint := "https://" + listener.Addr().String() + "/anchor"
	transport, err := appstoreanchortls.NewWriter(appstoreanchortls.Config{Endpoint: endpoint, RootCAs: roots, Certificate: writerCert, ServiceKey: signer.Public().(ed25519.PublicKey), StoreID: h.StoreID()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	create, err := appstoreanchorrequest.NewCreate(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	genesisCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	reply, _, err := transport.Submit(genesisCtx, create)
	if err != nil || reply.Outcome() != appstoreanchorreply.Committed {
		t.Fatalf("initialize genesis: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(writerCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return directory, store, BindingParts{Endpoint: endpoint, RootsDER: [][]byte{caDER}, CertificateDER: writerCert.Certificate, PrivateDER: privateDER, ServiceKey: signer.Public().(ed25519.PublicKey), Header: h, DirectoryDev: dev, DirectoryIno: ino}
}
