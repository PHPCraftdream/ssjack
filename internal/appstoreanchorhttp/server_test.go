package appstoreanchorhttp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"net/http"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func post(t *testing.T, client *http.Client, endpoint string, request appstoreanchorrequest.Request, key ed25519.PublicKey) (appstoreanchorreply.Reply, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(deadline(t), http.MethodPost, endpoint, bytes.NewReader(request.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 353))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := appstoreanchorreply.Verify(body, key, appstoreanchorreply.Expected{Operation: appstoreanchorreply.Operation(request.Operation()), RequestID: request.RequestID(), StoreID: request.StoreID()})
	if err != nil {
		t.Fatal("signed reply rejected", err)
	}
	return reply, body
}

func TestActualMTLSCreateReserveCommitReadAndRestartReplay(t *testing.T) {
	b, dir := backend(t)
	f := certs(t, 10)
	server, endpoint := start(t, configuration("", f, b))
	reader, err := appstoreanchortls.New(appstoreanchortls.Config{Endpoint: endpoint, RootCAs: f.roots, Certificate: f.reader, ServiceKey: f.signer.Public().(ed25519.PublicKey), StoreID: storeID()})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	observed, err := reader.Read(deadline(t))
	if err != nil || observed.Outcome() != appstoreanchorreply.NotFound {
		t.Fatal("initial read", err)
	}
	transport := transport(f, f.writer)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	public := f.signer.Public().(ed25519.PublicKey)
	create, err := appstoreanchorrequest.NewCreate(storeID())
	if err != nil {
		t.Fatal(err)
	}
	created, original := post(t, client, endpoint, create, public)
	if created.Outcome() != appstoreanchorreply.Committed || created.ServiceVersion() != 0 {
		t.Fatal("creation")
	}
	genesis, _ := appstoreanchorstate.Genesis(storeID())
	entry, err := appstorejournal.NewEntry(0, [16]byte{2}, [16]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := appstoreanchorrequest.PlanReservation(genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	reserved, _ := post(t, client, endpoint, reserve, public)
	if reserved.Outcome() != appstoreanchorreply.Committed || reserved.ServiceVersion() != 1 {
		t.Fatal("reservation")
	}
	commit, err := appstoreanchorrequest.PlanCommit(reserve, [32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	committed, _ := post(t, client, endpoint, commit, public)
	if committed.Outcome() != appstoreanchorreply.Committed || committed.ServiceVersion() != 2 {
		t.Fatal("commit")
	}
	observed, err = reader.Read(deadline(t))
	expected, _ := commit.ProposedState()
	actual, ok := observed.State()
	if err != nil || !ok || actual != expected || observed.ServiceVersion() != 2 {
		t.Fatal("authenticated current state", err)
	}
	_, replayed := post(t, client, endpoint, create, public)
	if !bytes.Equal(original, replayed) {
		t.Fatal("replay returned later current state")
	}
	server.Close()
	b.Close()
	restarted, err := appstoreanchorledger.New(dir, storeID(), 16)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	_, nextEndpoint := start(t, configuration("", f, restarted))
	_, afterRestart := post(t, client, nextEndpoint, create, public)
	if !bytes.Equal(original, afterRestart) {
		t.Fatal("network restart replay changed original outcome")
	}
}

func TestOwnedCredentialsAndReaderMutationDenial(t *testing.T) {
	b, _ := backend(t)
	f := certs(t, 30)
	cfg := configuration("", f, b)
	_, endpoint := start(t, cfg)
	public := append(ed25519.PublicKey(nil), f.signer.Public().(ed25519.PublicKey)...)
	clear(f.signer)
	clear(f.server.Certificate[0])
	clear(f.server.PrivateKey.(ed25519.PrivateKey))
	cfg.Bindings[1].Role = 2
	tr := transport(f, f.reader)
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	create, err := appstoreanchorrequest.NewCreate(storeID())
	if err != nil {
		t.Fatal(err)
	}
	rejected, body := post(t, client, endpoint, create, public)
	if rejected.Outcome() != appstoreanchorreply.Rejected || binary.BigEndian.Uint16(body[56:58]) != 0 {
		t.Fatal("reader mutation or caller mutation bypassed fixed role")
	}
}

func TestConfigurationAndSharedClose(t *testing.T) {
	b, _ := backend(t)
	f := certs(t, 40)
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Authority = "127.0.0.1:0" },
		func(c *Config) { c.ClientCAs = nil },
		func(c *Config) { c.SigningKey = make([]byte, 64) },
		func(c *Config) { c.Bindings = append(c.Bindings, c.Bindings[0]) },
		func(c *Config) { c.Bindings[0].StoreID = [16]byte{2} },
		func(c *Config) { c.Bindings[0].CredentialID = [32]byte{} },
		func(c *Config) { c.Certificate.PrivateKey = f.reader.PrivateKey },
	} {
		cfg := configuration("127.0.0.1:443", f, b)
		mutate(&cfg)
		if s, err := New(cfg); s != nil || err != ErrInvalid {
			t.Fatal("invalid configuration accepted", err)
		}
	}
	s, err := New(configuration("127.0.0.1:443", f, b))
	if err != nil {
		t.Fatal(err)
	}
	owned := s.state.signer
	alias := *s
	if err := alias.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(owned, make([]byte, len(owned))) || s.state.signer != nil {
		t.Fatal("owned signer retained")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateOwnershipAndMalformedKey(t *testing.T) {
	f := certs(t, 50)
	owned, err := ownCertificate(f.server)
	if err != nil {
		t.Fatal(err)
	}
	saved := append([]byte(nil), owned.Certificate[0]...)
	clear(f.server.Certificate[0])
	clear(f.server.PrivateKey.(ed25519.PrivateKey))
	if !bytes.Equal(owned.Certificate[0], saved) || bytes.Equal(owned.PrivateKey.(ed25519.PrivateKey), f.server.PrivateKey.(ed25519.PrivateKey)) {
		t.Fatal("TLS credentials not owned")
	}
	f.server.PrivateKey = ed25519.PrivateKey{1}
	if _, err := ownCertificate(f.server); err != ErrInvalid {
		t.Fatal("malformed private key accepted")
	}
}
