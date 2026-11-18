// Package anchorfixture builds real TLS anchor services and store directories for tests.
package anchorfixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorhttp"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

// WriterFixture builds a real TLS transport and durable anchor service for snapshot tests.
func WriterFixture(t *testing.T, role appstoreanchorcore.Role) (*appstoreanchortls.Writer, *appstoreanchorledger.Backend, *appstorefile.Directory, appstoreheader.Header) {
	w, backend, directory, h, _ := WriterFixtureWithCredential(t, role)
	return w, backend, directory, h
}

func WriterFixtureWithCredential(t *testing.T, role appstoreanchorcore.Role) (*appstoreanchortls.Writer, *appstoreanchorledger.Backend, *appstorefile.Directory, appstoreheader.Header, [32]byte) {
	w, backend, directory, h, credential, _ := WriterFixtureWithFault(t, role)
	return w, backend, directory, h, credential
}

type faultListener struct {
	net.Listener
	fault *ReplyFault
}

func (l *faultListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.fault.Accepted.Add(1)
		return &faultConn{Conn: conn, fault: l.fault}, nil
	}
	return nil, err
}

type faultConn struct {
	net.Conn
	fault *ReplyFault
}

func (c *faultConn) Write(p []byte) (int, error) {
	if c.fault.Armed.Load() && c.fault.committed() && c.fault.Drop.Swap(false) {
		c.fault.Dropped.Store(true)
		c.fault.Armed.Store(false)
		_ = c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(p)
}

type ReplyFault struct {
	Armed    atomic.Bool
	Drop     atomic.Bool
	Dropped  atomic.Bool
	Accepted atomic.Int64
	Backend  *appstoreanchorledger.Backend
	Grant    appstoreanchorcore.Grant
	Target   appstoreanchorstate.State
	Reader   *appstoreanchortls.Client
}

func (f *ReplyFault) committed() bool {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return false
	}
	request, err := appstoreanchorrequest.NewRead(f.Grant.StoreID(), id)
	if err != nil {
		return false
	}
	coreRequest, err := appstoreanchorcore.Parse(request.Bytes(), f.Grant.StoreID())
	if err != nil {
		return false
	}
	result, err := f.Backend.Execute(coreRequest, f.Grant)
	if err != nil {
		return false
	}
	unsigned, err := result.Unsigned()
	if err != nil {
		return false
	}
	state, err := appstoreanchorstate.Parse(unsigned[64:256], f.Grant.StoreID())
	return err == nil && state.Bytes() == f.Target.Bytes()
}

func WriterFixtureWithFault(t *testing.T, role appstoreanchorcore.Role) (*appstoreanchortls.Writer, *appstoreanchorledger.Backend, *appstorefile.Directory, appstoreheader.Header, [32]byte, *ReplyFault) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux durable service required")
	}
	h := Header(t)
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	directory, err := appstorefile.Open(root, h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	backendPath := t.TempDir()
	if err := os.Chmod(backendPath, 0700); err != nil {
		t.Fatal(err)
	}
	ledgerRoot, err := os.Open(backendPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledgerRoot.Close() })
	backend, err := appstoreanchorledger.New(ledgerRoot, h.StoreID(), 64)
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
	serverCert, writerCert, readerCert := leaf(72, x509.ExtKeyUsageServerAuth), leaf(73, x509.ExtKeyUsageClientAuth), leaf(74, x509.ExtKeyUsageClientAuth)
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{75}, 32))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fault := &ReplyFault{}
	wrappedListener := &faultListener{Listener: listener, fault: fault}
	service, err := appstoreanchorhttp.New(appstoreanchorhttp.Config{Authority: listener.Addr().String(), Certificate: serverCert, ClientCAs: roots, SigningKey: signer, Bindings: []appstoreanchorhttp.Binding{{CredentialID: sha256.Sum256(writerCert.Certificate[0]), StoreID: h.StoreID(), Role: appstoreanchorcore.Writer, Backend: backend}, {CredentialID: sha256.Sum256(readerCert.Certificate[0]), StoreID: h.StoreID(), Role: appstoreanchorcore.Reader, Backend: backend}}})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serviceCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(serviceCtx, wrappedListener) }()
	t.Cleanup(func() { cancel(); _ = listener.Close(); _ = service.Close(); <-done })
	makeWriter := func(cert tls.Certificate) *appstoreanchortls.Writer {
		w, e := appstoreanchortls.NewWriter(appstoreanchortls.Config{Endpoint: "https://" + listener.Addr().String() + "/anchor", RootCAs: roots, Certificate: cert, ServiceKey: signer.Public().(ed25519.PublicKey), StoreID: h.StoreID()})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = w.Close() })
		return w
	}
	genesisWriter := makeWriter(writerCert)
	create, err := appstoreanchorrequest.NewCreate(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancelOp := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelOp()
	created, _, err := genesisWriter.Submit(ctx, create)
	if err != nil || created.Outcome() != appstoreanchorreply.Committed {
		t.Fatalf("initialize writer genesis: %v", err)
	}
	readClient, err := appstoreanchortls.New(appstoreanchortls.Config{Endpoint: "https://" + listener.Addr().String() + "/anchor", RootCAs: roots, Certificate: readerCert, ServiceKey: signer.Public().(ed25519.PublicKey), StoreID: h.StoreID()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readClient.Close() })
	fault.Reader = readClient
	if role == appstoreanchorcore.Reader {
		return makeWriter(readerCert), backend, directory, h, sha256.Sum256(readerCert.Certificate[0]), fault
	}
	fault.Backend = backend
	fault.Grant, _ = appstoreanchorcore.NewGrant(h.StoreID(), sha256.Sum256(writerCert.Certificate[0]), appstoreanchorcore.Writer)
	return genesisWriter, backend, directory, h, sha256.Sum256(writerCert.Certificate[0]), fault
}
