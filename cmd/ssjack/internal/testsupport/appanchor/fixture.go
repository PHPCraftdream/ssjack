// Package appanchor provides the shared no-install application-store anchor
// fixture reused by the appstore replay tests and the delivery acceptance
// suite. It starts an isolated anchor service, provisions genesis state and a
// writer transport, and records connection/drop fault controls.
package appanchor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
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
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
)

// Fixture is the installed-store-free anchor environment. Fields are exported
// because the fixture is shared across test packages.
type Fixture struct {
	Dir, Master, Secret, Endpoint string
	Store                         [16]byte
	CADER, PrivateDER, ServiceKey []byte
	ClientChain                   [][]byte
	Backend                       *appstoreanchorledger.Backend
	Client                        tls.Certificate
	Transport                     *appstoreanchortls.Writer
	Accepted                      atomic.Int64
	Drop, Dropped, DenyRead       atomic.Bool
}

type listener struct {
	net.Listener
	f *Fixture
}

func (l *listener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	l.f.Accepted.Add(1)
	if l.f.Dropped.Load() && l.f.DenyRead.Load() {
		_ = c.Close()
	}
	return conn{Conn: c, f: l.f}, nil
}

type conn struct {
	net.Conn
	f *Fixture
}

func (c conn) Write(p []byte) (int, error) {
	if c.f.Drop.Load() && c.f.AnchoredCommitted() && c.f.Drop.CompareAndSwap(true, false) {
		c.f.Dropped.Store(true)
		_ = c.Conn.Close()
		return 0, errors.New("dropped committed response")
	}
	return c.Conn.Write(p)
}

// AnchoredCommitted reports whether the authority has exactly one committed
// journal entry, without any CLI involvement.
func (f *Fixture) AnchoredCommitted() bool {
	var id [16]byte
	_, _ = rand.Read(id[:])
	req, e := appstoreanchorrequest.NewRead(f.Store, id)
	if e != nil {
		return false
	}
	parsed, e := appstoreanchorcore.Parse(req.Bytes(), f.Store)
	if e != nil {
		return false
	}
	grant, e := appstoreanchorcore.NewGrant(f.Store, sha256.Sum256(f.Client.Certificate[0]), appstoreanchorcore.Writer)
	if e != nil {
		return false
	}
	result, e := f.Backend.Execute(parsed, grant)
	if e != nil {
		return false
	}
	raw, e := result.Unsigned()
	if e != nil {
		return false
	}
	state, e := appstoreanchorstate.Parse(raw[64:256], f.Store)
	return e == nil && state.Sequence() == 1
}

// AnchorState returns the current signed authority state.
func (f *Fixture) AnchorState(t *testing.T) appstoreanchorstate.State {
	t.Helper()
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		t.Fatal(e)
	}
	req, e := appstoreanchorrequest.NewRead(f.Store, id)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := appstoreanchorcore.Parse(req.Bytes(), f.Store)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := appstoreanchorcore.NewGrant(f.Store, sha256.Sum256(f.Client.Certificate[0]), appstoreanchorcore.Writer)
	if e != nil {
		t.Fatal(e)
	}
	result, e := f.Backend.Execute(parsed, grant)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := result.Unsigned()
	if e != nil {
		t.Fatal(e)
	}
	state, e := appstoreanchorstate.Parse(raw[64:256], f.Store)
	if e != nil || !state.Valid() {
		t.Fatalf("invalid backend state: %v", e)
	}
	return state
}

// New builds the no-install fixture: anchor service, genesis state, writer
// transport and client certificate material, without an installed store.
func New(t *testing.T) *Fixture {
	t.Helper()
	if !appstoreentry.Supported() {
		t.Skip("Linux appstore acceptance")
	}
	f := &Fixture{Dir: filepath.Join(t.TempDir(), "install"), Store: [16]byte{91}, Master: "scoped master", Secret: "scoped secret"}
	if e := os.Mkdir(f.Dir, 0700); e != nil {
		t.Fatal(e)
	}
	lp := t.TempDir()
	if e := os.Chmod(lp, 0700); e != nil {
		t.Fatal(e)
	}
	root, e := os.Open(lp)
	if e != nil {
		t.Fatal(e)
	}
	f.Backend, e = appstoreanchorledger.New(root, f.Store, 64)
	_ = root.Close()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.Backend.Close() })
	now := time.Now()
	cak := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32))
	cat := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, cat, cat, cak.Public(), cak)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(seed byte, use x509.ExtKeyUsage) tls.Certificate {
		k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(seed)), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{use}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, x := x509.CreateCertificate(rand.Reader, tmpl, ca, k.Public(), cak)
		if x != nil {
			t.Fatal(x)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: k}
	}
	server, client := leaf(82, x509.ExtKeyUsageServerAuth), leaf(83, x509.ExtKeyUsageClientAuth)
	f.Client = client
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{84}, 32))
	netListener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	wrapped := &listener{Listener: netListener, f: f}
	service, e := appstoreanchorhttp.New(appstoreanchorhttp.Config{Authority: netListener.Addr().String(), Certificate: server, ClientCAs: roots, SigningKey: signer, Bindings: []appstoreanchorhttp.Binding{{CredentialID: sha256.Sum256(client.Certificate[0]), StoreID: f.Store, Role: appstoreanchorcore.Writer, Backend: f.Backend}}})
	if e != nil {
		_ = netListener.Close()
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, wrapped) }()
	t.Cleanup(func() { cancel(); _ = netListener.Close(); _ = service.Close(); <-done })
	f.Endpoint = "https://" + netListener.Addr().String() + "/anchor"
	f.Transport, e = appstoreanchortls.NewWriter(appstoreanchortls.Config{Endpoint: f.Endpoint, RootCAs: roots, Certificate: client, ServiceKey: signer.Public().(ed25519.PublicKey), StoreID: f.Store})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.Transport.Close() })
	create, e := appstoreanchorrequest.NewCreate(f.Store)
	if e != nil {
		t.Fatal(e)
	}
	opctx, opcancel := context.WithTimeout(context.Background(), 60*time.Second)
	created, _, e := f.Transport.Submit(opctx, create)
	opcancel()
	if e != nil || created.Outcome() != appstoreanchorreply.Committed {
		t.Fatalf("initialize anchor genesis: %v", e)
	}
	if state, present := created.State(); !present || !state.Valid() || state.Sequence() != 0 || state.JournalCount() != 0 || state.StoreID() != f.Store {
		t.Fatal("invalid genesis state")
	}
	f.CADER = append([]byte(nil), caDER...)
	private, e := x509.MarshalPKCS8PrivateKey(client.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	f.PrivateDER = private
	f.ClientChain = make([][]byte, len(client.Certificate))
	for i := range client.Certificate {
		f.ClientChain[i] = append([]byte(nil), client.Certificate[i]...)
	}
	f.ServiceKey = append([]byte(nil), signer.Public().(ed25519.PublicKey)...)
	t.Cleanup(func() {
		clear(f.CADER)
		clear(f.PrivateDER)
		clear(f.ServiceKey)
		clearDERs(f.ClientChain)
		f.CADER = nil
		f.PrivateDER = nil
		f.ServiceKey = nil
		f.ClientChain = nil
	})
	return f
}

func clearDERs(v [][]byte) {
	for i := range v {
		clear(v[i])
	}
}
