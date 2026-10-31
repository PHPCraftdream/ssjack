//go:build linux && amd64

package main

import (
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
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorhttp"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
)

type syntheticAnchor struct {
	endpoint                             string
	caDER, privateDER, serviceKey        []byte
	clientChain                          [][]byte
	store                                [16]byte
	backend                              *appstoreanchorledger.Backend
	transport                            *appstoreanchortls.Writer
	service                              *appstoreanchorhttp.Server
	listener                             net.Listener
	cancel                               context.CancelFunc
	done                                 chan error
	dir                                  string
	serverPrivate, clientPrivate, signer ed25519.PrivateKey
}

func newSyntheticAnchor() (_ *syntheticAnchor, err error) {
	a := &syntheticAnchor{}
	defer func() {
		if err != nil {
			_ = a.Close()
		}
	}()
	if _, err = rand.Read(a.store[:]); err != nil {
		return nil, err
	}
	parent, e := os.MkdirTemp("", "ssjack-lab-anchor-")
	if e != nil {
		return nil, e
	}
	a.dir = parent
	if e = os.Chmod(parent, 0700); e != nil {
		return nil, e
	}
	root, e := os.Open(parent)
	if e != nil {
		return nil, e
	}
	a.backend, e = appstoreanchorledger.New(root, a.store, 64)
	closeErr := root.Close()
	if e != nil {
		return nil, e
	}
	if closeErr != nil {
		return nil, closeErr
	}
	now := time.Now()
	_, caKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	defer clear(caKey)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	a.caDER, e = x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if e != nil {
		return nil, e
	}
	ca, e := x509.ParseCertificate(a.caDER)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, error) {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return tls.Certificate{}, e
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
		if e != nil {
			clear(key)
			return tls.Certificate{}, e
		}
		return tls.Certificate{Certificate: [][]byte{der, a.caDER}, PrivateKey: key}, nil
	}
	serverCert, e := leaf(2, x509.ExtKeyUsageServerAuth)
	if e != nil {
		return nil, e
	}
	clientCert, e := leaf(3, x509.ExtKeyUsageClientAuth)
	if e != nil {
		clear(serverCert.PrivateKey.(ed25519.PrivateKey))
		return nil, e
	}
	a.serverPrivate = serverCert.PrivateKey.(ed25519.PrivateKey)
	a.clientPrivate = clientCert.PrivateKey.(ed25519.PrivateKey)
	_, a.signer, e = ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	a.privateDER, e = x509.MarshalPKCS8PrivateKey(a.clientPrivate)
	if e != nil {
		return nil, e
	}
	a.clientChain = [][]byte{append([]byte(nil), clientCert.Certificate[0]...), append([]byte(nil), a.caDER...)}
	a.listener, e = net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	credential := sha256.Sum256(clientCert.Certificate[0])
	a.service, e = appstoreanchorhttp.New(appstoreanchorhttp.Config{Authority: a.listener.Addr().String(), Certificate: serverCert, ClientCAs: roots, SigningKey: a.signer, Bindings: []appstoreanchorhttp.Binding{{CredentialID: credential, StoreID: a.store, Role: appstoreanchorcore.Writer, Backend: a.backend}}})
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.done = make(chan error, 1)
	go func() { a.done <- a.service.Serve(ctx, a.listener) }()
	a.endpoint = "https://" + a.listener.Addr().String() + "/anchor"
	a.serviceKey = append([]byte(nil), a.signer.Public().(ed25519.PublicKey)...)
	a.transport, e = appstoreanchortls.NewWriter(appstoreanchortls.Config{Endpoint: a.endpoint, RootCAs: roots, Certificate: clientCert, ServiceKey: ed25519.PublicKey(a.serviceKey), StoreID: a.store})
	if e != nil {
		return nil, e
	}
	req, e := appstoreanchorrequest.NewCreate(a.store)
	if e != nil {
		return nil, e
	}
	opctx, cancelOp := context.WithTimeout(context.Background(), 10*time.Second)
	reply, _, submitErr := a.transport.Submit(opctx, req)
	cancelOp()
	if submitErr != nil || reply.Outcome() != appstoreanchorreply.Committed {
		return nil, errors.New("synthetic anchor initialization failed")
	}
	genesis, genesisErr := appstoreanchorstate.Genesis(a.store)
	state, hasState := reply.State()
	if genesisErr != nil || !hasState || state != genesis || state.Sequence() != 0 || state.JournalCount() != 0 || state.StoreID() != a.store || !reply.SignatureValid() {
		return nil, errors.New("synthetic anchor genesis mismatch")
	}
	return a, nil
}
func (a *syntheticAnchor) Close() error {
	if a == nil {
		return nil
	}
	if a.transport != nil {
		_ = a.transport.Close()
	}
	if a.cancel != nil {
		a.cancel()
	}
	if a.listener != nil {
		_ = a.listener.Close()
	}
	if a.service != nil {
		_ = a.service.Close()
	}
	if a.done != nil {
		select {
		case <-a.done:
		case <-time.After(2 * time.Second):
		}
	}
	if a.backend != nil {
		_ = a.backend.Close()
	}
	for _, k := range [][]byte{a.caDER, a.privateDER, a.serviceKey, a.serverPrivate, a.clientPrivate, a.signer} {
		clear(k)
	}
	for _, d := range a.clientChain {
		clear(d)
	}
	if a.dir != "" {
		_ = os.RemoveAll(filepath.Clean(a.dir))
	}
	return nil
}
