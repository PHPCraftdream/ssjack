package appstoreanchortls

import (
	"bytes"
	"context"
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
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorhttp"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorresult"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
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

func signedMutationReply(t *testing.T, raw []byte, signer ed25519.PrivateKey, mode string, other appstoreanchorstate.State) []byte {
	t.Helper()
	if len(raw) != 304 || raw[8] != 3 {
		t.Error("noncanonical mutation fixture input")
		return nil
	}
	b := make([]byte, 352)
	copy(b[:8], "SSASRSP1")
	b[8], b[9] = raw[8], 5
	copy(b[16:32], raw[32:48])
	copy(b[32:48], raw[16:32])
	if mode == "wrong-state" {
		b[9] = 2
		binary.BigEndian.PutUint64(b[48:56], 1)
		binary.BigEndian.PutUint16(b[56:58], 192)
		state, hash := other.Bytes(), other.Hash()
		copy(b[64:256], state[:])
		copy(b[256:288], hash[:])
	}
	if mode == "wrong-id" {
		b[16] ^= 1
	}
	copy(b[288:], ed25519.Sign(signer, b[:288]))
	return b
}

func liveWriterConfig(t *testing.T, role appstoreanchorcore.Role) Config {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux durable service required")
	}
	f := fixture(t, 140)
	cfg := config("https://127.0.0.1:443", f)
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	backend, err := appstoreanchorledger.New(dir, cfg.StoreID, 16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service, err := appstoreanchorhttp.New(appstoreanchorhttp.Config{
		Authority: listener.Addr().String(), Certificate: f.server, ClientCAs: f.roots, SigningKey: f.signer,
		Bindings: []appstoreanchorhttp.Binding{{CredentialID: sha256.Sum256(f.client.Certificate[0]), StoreID: cfg.StoreID, Role: role, Backend: backend}},
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, listener) }()
	t.Cleanup(func() { cancel(); listener.Close(); service.Close(); <-done })
	cfg.Endpoint = "https://" + listener.Addr().String() + "/anchor"
	return cfg
}

func TestWriterAgainstActualDurableTLSService(t *testing.T) {
	cfg := liveWriterConfig(t, appstoreanchorcore.Writer)
	writer, err := NewWriter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	observed, err := writer.Read(readContext(t))
	if err != nil || observed.Outcome() != appstoreanchorreply.NotFound {
		t.Fatal("initial read", err)
	}
	create, err := appstoreanchorrequest.NewCreate(cfg.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	genesis, _ := appstoreanchorstate.Genesis(cfg.StoreID)
	entry, _ := appstorejournal.NewEntry(0, [16]byte{2}, [16]byte{3})
	reserve, err := appstoreanchorrequest.PlanReservation(genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := appstoreanchorrequest.PlanCommit(reserve, [32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	for index, request := range []appstoreanchorrequest.Request{create, reserve, commit} {
		reply, result, err := writer.Submit(readContext(t), request)
		if err != nil || result != appstoreanchorresult.ExactRecordedResult || reply.ServiceVersion() != uint64(index) {
			t.Fatalf("mutation %d: %v", index, err)
		}
	}
	replayed, result, err := writer.Submit(readContext(t), create)
	if err != nil || result != appstoreanchorresult.ExactRecordedResult || replayed.ServiceVersion() != 0 {
		t.Fatal("original outcome replay", err)
	}
	observed, err = writer.Read(readContext(t))
	if err != nil || observed.ServiceVersion() != 2 {
		t.Fatal("reconciliation read", err)
	}
	otherEntry, _ := appstorejournal.NewEntry(0, [16]byte{6}, [16]byte{7})
	stale, err := appstoreanchorrequest.PlanReservation(genesis, otherEntry)
	if err != nil {
		t.Fatal(err)
	}
	conflict, result, err := writer.Submit(readContext(t), stale)
	if err != nil || result != appstoreanchorresult.ReadRequired || conflict.Outcome() != appstoreanchorreply.Conflict {
		t.Fatal("stale CAS classification", err)
	}
	readerConfig := liveWriterConfig(t, appstoreanchorcore.Reader)
	reader, err := NewWriter(readerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	rejected, result, err := reader.Submit(readContext(t), create)
	if err != nil || result != appstoreanchorresult.ReportedRejected || rejected.Outcome() != appstoreanchorreply.Rejected {
		t.Fatal("reader credential bypassed server role", err)
	}
}
