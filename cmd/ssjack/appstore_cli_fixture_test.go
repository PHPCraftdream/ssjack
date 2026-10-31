package main

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
	"strings"
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
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
)

type appstoreReplayFixture struct {
	dir, master, secret     string
	store                   [16]byte
	backend                 *appstoreanchorledger.Backend
	transport               *appstoreanchortls.Writer
	client                  tls.Certificate
	drop, dropped, denyRead atomic.Bool
	accepted                atomic.Int64
}
type replayListener struct {
	net.Listener
	f *appstoreReplayFixture
}

func (l *replayListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	l.f.accepted.Add(1)
	if l.f.dropped.Load() && l.f.denyRead.Load() {
		_ = c.Close()
		return replayConn{Conn: c, f: l.f}, nil
	}
	return replayConn{Conn: c, f: l.f}, nil
}

type replayConn struct {
	net.Conn
	f *appstoreReplayFixture
}

func (c replayConn) Write(p []byte) (int, error) {
	if c.f.drop.Load() && c.f.committed() && c.f.drop.CompareAndSwap(true, false) {
		c.f.dropped.Store(true)
		_ = c.Conn.Close()
		return 0, errors.New("dropped committed response")
	}
	return c.Conn.Write(p)
}
func (f *appstoreReplayFixture) committed() bool {
	var id [16]byte
	_, _ = rand.Read(id[:])
	req, e := appstoreanchorrequest.NewRead(f.store, id)
	if e != nil {
		return false
	}
	parsed, e := appstoreanchorcore.Parse(req.Bytes(), f.store)
	if e != nil {
		return false
	}
	grant, e := appstoreanchorcore.NewGrant(f.store, sha256.Sum256(f.client.Certificate[0]), appstoreanchorcore.Writer)
	if e != nil {
		return false
	}
	result, e := f.backend.Execute(parsed, grant)
	if e != nil {
		return false
	}
	raw, e := result.Unsigned()
	if e != nil {
		return false
	}
	state, e := appstoreanchorstate.Parse(raw[64:256], f.store)
	return e == nil && state.Sequence() == 1
}
func (f *appstoreReplayFixture) input(values ...[]byte) func() {
	old := appstoreReadInput
	i := 0
	appstoreReadInput = func(string, bool) ([]byte, error) {
		if i >= len(values) {
			return nil, os.ErrClosed
		}
		v := append([]byte(nil), values[i]...)
		i++
		return v, nil
	}
	return func() { appstoreReadInput = old }
}
func (f *appstoreReplayFixture) anchorState(t *testing.T) appstoreanchorstate.State {
	t.Helper()
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		t.Fatal(e)
	}
	req, e := appstoreanchorrequest.NewRead(f.store, id)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := appstoreanchorcore.Parse(req.Bytes(), f.store)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := appstoreanchorcore.NewGrant(f.store, sha256.Sum256(f.client.Certificate[0]), appstoreanchorcore.Writer)
	if e != nil {
		t.Fatal(e)
	}
	result, e := f.backend.Execute(parsed, grant)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := result.Unsigned()
	if e != nil {
		t.Fatal(e)
	}
	state, e := appstoreanchorstate.Parse(raw[64:256], f.store)
	if e != nil || !state.Valid() {
		t.Fatalf("invalid backend state: %v", e)
	}
	return state
}
func (f *appstoreReplayFixture) anchorSeq(t *testing.T) uint64 {
	return f.anchorState(t).Sequence()
}
func noSecretOutput(t *testing.T, s string, secrets ...string) {
	t.Helper()
	for _, v := range secrets {
		if v != "" && strings.Contains(s, v) {
			t.Fatal("CLI disclosed secret")
		}
	}
}
func newAppstoreReplayFixture(t *testing.T) *appstoreReplayFixture {
	t.Helper()
	if !appstoreentry.Supported() {
		t.Skip("Linux appstore acceptance")
	}
	f := &appstoreReplayFixture{dir: filepath.Join(t.TempDir(), "install"), store: [16]byte{91}, master: "scoped master", secret: "scoped secret"}
	if e := os.Mkdir(f.dir, 0700); e != nil {
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
	f.backend, e = appstoreanchorledger.New(root, f.store, 64)
	_ = root.Close()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.backend.Close() })
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
	f.client = client
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{84}, 32))
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	wrapped := &replayListener{Listener: listener, f: f}
	service, e := appstoreanchorhttp.New(appstoreanchorhttp.Config{Authority: listener.Addr().String(), Certificate: server, ClientCAs: roots, SigningKey: signer, Bindings: []appstoreanchorhttp.Binding{{CredentialID: sha256.Sum256(client.Certificate[0]), StoreID: f.store, Role: appstoreanchorcore.Writer, Backend: f.backend}}})
	if e != nil {
		_ = listener.Close()
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, wrapped) }()
	t.Cleanup(func() { cancel(); _ = listener.Close(); _ = service.Close(); <-done })
	endpoint := "https://" + listener.Addr().String() + "/anchor"
	f.transport, e = appstoreanchortls.NewWriter(appstoreanchortls.Config{Endpoint: endpoint, RootCAs: roots, Certificate: client, ServiceKey: signer.Public().(ed25519.PublicKey), StoreID: f.store})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.transport.Close() })
	create, e := appstoreanchorrequest.NewCreate(f.store)
	if e != nil {
		t.Fatal(e)
	}
	opctx, opcancel := context.WithTimeout(context.Background(), 60*time.Second)
	created, _, e := f.transport.Submit(opctx, create)
	opcancel()
	if e != nil || created.Outcome() != appstoreanchorreply.Committed {
		t.Fatalf("initialize anchor genesis: %v", e)
	}
	if state, present := created.State(); !present || !state.Valid() || state.Sequence() != 0 || state.JournalCount() != 0 || state.StoreID() != f.store {
		t.Fatal("invalid genesis state")
	}
	private, e := x509.MarshalPKCS8PrivateKey(client.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	store, e := appstoreentry.Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	dev, ino, e := store.Identity()
	if e != nil {
		t.Fatal(e)
	}
	h, e := makeInstallationHeader(f.store)
	if e != nil {
		t.Fatal(e)
	}
	pub := signer.Public().(ed25519.PublicKey)
	installctx, installcancel := context.WithTimeout(context.Background(), 60*time.Second)
	encoded, e := appstorecrypto.NewInstallation(installctx, h, []byte(f.master), appstorecrypto.Binding{Endpoint: endpoint, RootsDER: [][]byte{caDER}, CertificateDER: client.Certificate, PrivateDER: private, ServiceKey: pub, Header: h, DirectoryDev: dev, DirectoryIno: ino})
	installcancel()
	clear(private)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Install(encoded); e != nil {
		t.Fatal(e)
	}
	clear(encoded)
	return f
}
