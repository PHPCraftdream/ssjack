package appstoreanchorhttp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func TestHTTPAndCertificateRefusals(t *testing.T) {
	b, _ := backend(t)
	f := certs(t, 70)
	_, endpoint := start(t, configuration("", f, b))
	create, _ := appstoreanchorrequest.NewCreate(storeID())
	for _, name := range []string{"unknown-cert", "unknown-store", "missing-cert", "TLS12", "query", "host", "method", "origin", "oversize", "malformed"} {
		t.Run(name, func(t *testing.T) {
			certificate := f.writer
			if name == "unknown-cert" {
				certificate = f.unknown
			} else if name == "missing-cert" {
				certificate = tls.Certificate{}
			}
			tr := transport(f, certificate)
			defer tr.CloseIdleConnections()
			if name == "missing-cert" {
				tr.TLSClientConfig.Certificates = nil
			}
			if name == "TLS12" {
				tr.TLSClientConfig.MinVersion = tls.VersionTLS12
				tr.TLSClientConfig.MaxVersion = tls.VersionTLS12
			}
			raw := create.Bytes()
			if name == "unknown-store" {
				foreign, err := appstoreanchorrequest.NewCreate([16]byte{2})
				if err != nil {
					t.Fatal(err)
				}
				raw = foreign.Bytes()
			}
			target := endpoint
			if name == "query" {
				target += "?x=1"
			}
			if name == "oversize" {
				raw = make([]byte, 305)
			}
			if name == "malformed" {
				raw[0] ^= 1
			}
			request, err := http.NewRequestWithContext(deadline(t), http.MethodPost, target, bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/octet-stream")
			if name == "host" {
				request.Host = "elsewhere.invalid:443"
			}
			if name == "method" {
				request.Method = http.MethodGet
			}
			if name == "origin" {
				request.Header.Set("Origin", "https://browser.invalid")
			}
			response, err := (&http.Client{Transport: tr}).Do(request)
			if name == "missing-cert" || name == "TLS12" {
				if err == nil {
					response.Body.Close()
					t.Fatal("TLS profile accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			expected := http.StatusBadRequest
			if name == "unknown-cert" || name == "unknown-store" {
				expected = http.StatusForbidden
			}
			if name == "oversize" {
				expected = http.StatusRequestEntityTooLarge
			}
			if response.StatusCode != expected {
				t.Fatalf("status %d, want %d", response.StatusCode, expected)
			}
		})
	}
}

func TestCallerRootPoolMutationDoesNotEnrollAnotherCA(t *testing.T) {
	b, _ := backend(t)
	f := certs(t, 90)
	other := certs(t, 100)
	cfg := configuration("", f, b)
	cfg.Bindings[0].CredentialID = fingerprint(other.writer)
	_, endpoint := start(t, cfg)
	f.roots.AddCert(other.root)
	tr := transport(f, other.writer)
	defer tr.CloseIdleConnections()
	read, _ := appstoreanchorrequest.NewRead(storeID(), [16]byte{9})
	request, err := http.NewRequestWithContext(deadline(t), http.MethodPost, endpoint, bytes.NewReader(read.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := (&http.Client{Transport: tr}).Do(request)
	if err == nil {
		response.Body.Close()
		t.Fatal("caller CA mutation expanded client trust")
	}
}

type response struct {
	header  http.Header
	body    bytes.Buffer
	entered chan struct{}
	release <-chan struct{}
}

func (r *response) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}
func (r *response) WriteHeader(int)                  {}
func (r *response) Write(b []byte) (int, error)      { return r.body.Write(b) }
func (r *response) SetWriteDeadline(time.Time) error { return nil }
func (r *response) FlushError() error {
	if r.entered != nil {
		close(r.entered)
		<-r.release
	}
	return nil
}

func TestOutstandingLeaseSurvivesThroughFlush(t *testing.T) {
	b, _ := backend(t)
	f := certs(t, 120)
	s, err := New(configuration("127.0.0.1:443", f, b))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	public := f.signer.Public().(ed25519.PublicKey)
	peer, err := x509.ParseCertificate(f.writer.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func(raw []byte) *http.Request {
		return &http.Request{Method: http.MethodPost, ProtoMajor: 1, Host: "127.0.0.1:443", URL: &url.URL{Path: "/anchor"}, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw)), TLS: &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{peer}, VerifiedChains: [][]*x509.Certificate{{f.root}}}}
	}
	create, _ := appstoreanchorrequest.NewCreate(storeID())
	initial := &response{}
	s.state.serveHTTP(initial, makeRequest(create.Bytes()))
	genesis, _ := appstoreanchorstate.Genesis(storeID())
	entry, _ := appstorejournal.NewEntry(0, [16]byte{2}, [16]byte{3})
	reserve, err := appstoreanchorrequest.PlanReservation(genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	first := &response{entered: entered, release: release}
	go func() { s.state.serveHTTP(first, makeRequest(reserve.Bytes())); close(done) }()
	defer func() { close(release); <-done }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("response never reached flush")
	}
	firstReply, err := appstoreanchorreply.Verify(first.body.Bytes(), public, appstoreanchorreply.Expected{Operation: appstoreanchorreply.CAS, RequestID: reserve.RequestID(), StoreID: storeID()})
	if err != nil || firstReply.Outcome() != appstoreanchorreply.Committed {
		t.Fatal("fixture never committed before flush", err)
	}
	for _, changed := range []bool{false, true} {
		raw := reserve.Bytes()
		if changed {
			raw[48] ^= 1
		}
		duplicate := &response{}
		s.state.serveHTTP(duplicate, makeRequest(raw))
		reply, err := appstoreanchorreply.Verify(duplicate.body.Bytes(), public, appstoreanchorreply.Expected{Operation: appstoreanchorreply.CAS, RequestID: reserve.RequestID(), StoreID: storeID()})
		expected := appstoreanchorreply.Unknown
		if changed {
			expected = appstoreanchorreply.Rejected
		}
		if err != nil || reply.Outcome() != expected {
			t.Fatal("in-flight duplicate/collision misclassified", err)
		}
	}
}
