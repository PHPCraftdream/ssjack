package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
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
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func recordHeader(t *testing.T, total uint64) appstoreheader.Header {
	t.Helper()
	b := header(t).Bytes()
	binary.BigEndian.PutUint64(b[64:72], total)
	binary.BigEndian.PutUint32(b[72:76], uint32((total+1048575)/1048576))
	h, err := appstoreheader.Parse(b[:])
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func finalRecord(h appstoreheader.Header) []byte {
	b := append([]byte("FIN1"), make([]byte, 44)...)
	binary.BigEndian.PutUint64(b[4:12], h.PlaintextSize())
	binary.BigEndian.PutUint32(b[12:16], h.ChunkCount())
	copy(b[16:48], bytes.Repeat([]byte{0x77}, 32))
	return b
}

func oracleLayer(t *testing.T, master [32]byte, h appstoreheader.Header, index uint32, layer int, final bool, plain int) (cipher.AEAD, []byte, []byte) {
	t.Helper()
	keyPrefix, noncePrefix, label := "ssjack-appstore/v1/data/chunk/", "ssjack-appstore/v1/nonce", "SSAPP chunk layer"
	if final {
		keyPrefix, noncePrefix, label = "ssjack-appstore/v1/data/final/", "ssjack-appstore/v1/nonce/final", "SSAPP final layer"
	}
	store, snapshot, base := h.StoreID(), h.SnapshotID(), h.NonceBase()
	contextBytes := append([]byte(keyPrefix), store[:]...)
	contextBytes = append(contextBytes, snapshot[:]...)
	contextBytes = binary.BigEndian.AppendUint32(contextBytes, index)
	contextBytes = binary.BigEndian.AppendUint32(contextBytes, uint32(layer))
	key := hkdfOracle(master[:], string(contextBytes))
	block, err := aes.NewCipher(key[:])
	clear(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(noncePrefix), store[:]...)
	message = append(message, snapshot[:]...)
	message = binary.BigEndian.AppendUint32(message, index)
	message = binary.BigEndian.AppendUint32(message, uint32(layer))
	mac := hmac.New(sha256.New, base[:])
	_, _ = mac.Write(message)
	nonce := append([]byte(nil), mac.Sum(nil)[:12]...)
	raw := h.Bytes()
	aad := append(append([]byte(nil), raw[:208]...), base[:]...)
	for _, value := range []uint32{index, uint32(layer), uint32(plain), uint32(plain + 16000)} {
		aad = binary.BigEndian.AppendUint32(aad, value)
	}
	aad = append(aad, label...)
	return aead, nonce, aad
}

func oracleOpen(t *testing.T, master [32]byte, h appstoreheader.Header, index uint32, final bool, plain, last int, input []byte) []byte {
	t.Helper()
	data := append([]byte(nil), input...)
	for layer := 999; layer >= last; layer-- {
		aead, nonce, aad := oracleLayer(t, master, h, index, layer, final, plain)
		opened, err := aead.Open(data[:0], nonce, data, aad)
		if err != nil {
			t.Fatalf("independent layer %d: %v", layer, err)
		}
		clear(data[len(opened):])
		data = opened
	}
	return data
}

func oracleSeal(t *testing.T, master [32]byte, h appstoreheader.Header, index uint32, final bool, plain, first int, input []byte) []byte {
	t.Helper()
	data := make([]byte, len(input), plain+16000)
	copy(data, input)
	for layer := first; layer < 1000; layer++ {
		aead, nonce, aad := oracleLayer(t, master, h, index, layer, final, plain)
		data = aead.Seal(data[:0], nonce, data, aad)
	}
	return data
}

func TestExact1000LayersAndIndependentOracle(t *testing.T) {
	for _, row := range []struct {
		total uint64
		index uint32
		final bool
		size  int
	}{{2097152, 0, false, 1048576}, {1048579, 1, false, 3}, {1048576, ^uint32(0), true, 48}} {
		h := recordHeader(t, row.total)
		m, err := derive(context.Background(), h, []byte("synthetic layered-record fixture"), fake)
		if err != nil {
			t.Fatal(err)
		}
		plain := bytes.Repeat([]byte{0x42}, row.size)
		if row.final {
			plain = finalRecord(h)
		}
		before := append([]byte(nil), plain...)
		calls := 0
		sealed, err := m.transformRecord(context.Background(), h, row.index, row.final, plain, true, func(layer uint32) {
			if layer != uint32(calls) {
				t.Error("encryption layer order")
			}
			calls++
		})
		if err != nil || calls != 1000 || len(sealed) != len(plain)+16000 || !bytes.Equal(plain, before) {
			t.Fatalf("exact layered encryption: %v", err)
		}
		independent := oracleOpen(t, m.state.key, h, row.index, row.final, len(plain), 0, sealed)
		if !bytes.Equal(independent, plain) {
			t.Fatal("independent all-layer opening differs")
		}
		clear(independent)
		copyCipher := append([]byte(nil), sealed...)
		calls = 0
		opened, err := m.transformRecord(context.Background(), h, row.index, row.final, sealed, false, func(layer uint32) {
			if layer != uint32(999-calls) {
				t.Error("opening layer order")
			}
			calls++
		})
		if err != nil || calls != 1000 || !bytes.Equal(opened, plain) || !bytes.Equal(sealed, copyCipher) || !bytes.Equal(opened[len(opened):cap(opened)], make([]byte, cap(opened)-len(opened))) {
			t.Fatalf("all tags/input/tail: %v", err)
		}
		if !row.final && row.index == 0 {
			wrong, err := m.openRecord(context.Background(), h, 1, false, sealed)
			if !errors.Is(err, ErrAuthentication) || wrong != nil {
				t.Fatal("index binding was not authenticated")
			}
		}
		clear(opened)
		clear(sealed)
		clear(copyCipher)
		m.Close()
	}
}

func TestInnerTagAndHeaderBinding(t *testing.T) {
	h := header(t)
	m, err := derive(context.Background(), h, []byte("synthetic inner-tag fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	plain := finalRecord(h)
	sealed, err := m.sealRecord(context.Background(), h, ^uint32(0), true, plain)
	if err != nil {
		t.Fatal(err)
	}
	wrongMaster, err := derive(context.Background(), h, []byte("different synthetic passphrase"), fake)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := wrongMaster.openRecord(context.Background(), h, ^uint32(0), true, sealed)
	wrongMaster.Close()
	if !errors.Is(err, ErrAuthentication) || wrong != nil {
		t.Fatal("different passphrase master authenticated a record")
	}
	inner := oracleOpen(t, m.state.key, h, ^uint32(0), true, 48, 1, sealed)
	inner[len(inner)-1] ^= 1
	wrapped := oracleSeal(t, m.state.key, h, ^uint32(0), true, 48, 1, inner)
	opened, err := m.openRecord(context.Background(), h, ^uint32(0), true, wrapped)
	if !errors.Is(err, ErrAuthentication) || opened != nil {
		t.Fatal("invalid inner tag survived valid outer layers")
	}
	for _, offset := range []int{28, 208} {
		raw := h.Bytes()
		raw[offset] ^= 0x80
		changed, err := appstoreheader.Parse(raw[:])
		if err != nil {
			t.Fatal(err)
		}
		opened, err := m.openRecord(context.Background(), changed, ^uint32(0), true, sealed)
		if !errors.Is(err, ErrAuthentication) || opened != nil {
			t.Fatal("snapshot/nonce binding missing")
		}
	}
	badFinal := append([]byte(nil), plain...)
	badFinal[0] = 'X'
	validTags := oracleSeal(t, m.state.key, h, ^uint32(0), true, 48, 0, badFinal)
	opened, err = m.openRecord(context.Background(), h, ^uint32(0), true, validTags)
	if !errors.Is(err, ErrRecord) || opened != nil {
		t.Fatal("authenticated malformed final framing admitted")
	}
	clear(inner)
	clear(wrapped)
	clear(validTags)
	clear(sealed)
}

func snapshotWire(t *testing.T, m *Master, h appstoreheader.Header, badCatalog, badTranscript bool) ([]byte, ExpectedSnapshot) {
	t.Helper()
	if h.PlaintextSize() != 1048579 || h.ChunkCount() != 2 {
		t.Fatal("snapshot fixture expects catalog plus three bytes")
	}
	catalog := make([]byte, 1048576)
	defer clear(catalog)
	copy(catalog[:8], "SSCAT001")
	store, snapshot := h.StoreID(), h.SnapshotID()
	copy(catalog[8:24], store[:])
	copy(catalog[24:40], snapshot[:])
	binary.BigEndian.PutUint32(catalog[40:44], 1)
	copy(catalog[44:60], bytes.Repeat([]byte{3}, 16))
	copy(catalog[60:76], bytes.Repeat([]byte{4}, 16))
	binary.BigEndian.PutUint64(catalog[76:84], 3)
	copy(catalog[92:108], "bin")
	if badCatalog {
		binary.BigEndian.PutUint64(catalog[76:84], 4)
	}
	header := h.Bytes()
	wire := append([]byte(nil), header[:]...)
	for index, plain := range [][]byte{catalog, []byte("abc")} {
		ciphertext, err := m.sealRecord(context.Background(), h, uint32(index), false, plain)
		if err != nil {
			t.Fatal(err)
		}
		wire = binary.BigEndian.AppendUint32(wire, uint32(index))
		wire = binary.BigEndian.AppendUint32(wire, uint32(len(plain)))
		wire = binary.BigEndian.AppendUint32(wire, uint32(len(ciphertext)))
		wire = append(wire, ciphertext...)
		clear(ciphertext)
	}
	transcript := sha256.Sum256(wire[220:])
	final := finalRecord(h)
	copy(final[16:48], transcript[:])
	if badTranscript {
		final[16] ^= 1
	}
	ciphertext, err := m.sealRecord(context.Background(), h, ^uint32(0), true, final)
	clear(final)
	if err != nil {
		t.Fatal(err)
	}
	wire = append(wire, "FIN1"...)
	wire = binary.BigEndian.AppendUint64(wire, 16048)
	wire = append(wire, ciphertext...)
	clear(ciphertext)
	return wire, ExpectedSnapshot{StoreID: store, SnapshotID: snapshot, EncodedHash: sha256.Sum256(wire)}
}

// writerFixture builds a real TLS transport and durable anchor service for snapshot tests.
func writerFixture(t *testing.T, role appstoreanchorcore.Role) (*appstoreanchortls.Writer, *appstoreanchorledger.Backend, *appstorefile.Directory, appstoreheader.Header) {
	w, backend, directory, h, _ := writerFixtureWithCredential(t, role)
	return w, backend, directory, h
}

func writerFixtureWithCredential(t *testing.T, role appstoreanchorcore.Role) (*appstoreanchortls.Writer, *appstoreanchorledger.Backend, *appstorefile.Directory, appstoreheader.Header, [32]byte) {
	w, backend, directory, h, credential, _ := writerFixtureWithFault(t, role)
	return w, backend, directory, h, credential
}

type writerFaultListener struct {
	net.Listener
	fault *writerReplyFault
}

func (l *writerFaultListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.fault.accepted.Add(1)
		return &writerFaultConn{Conn: conn, fault: l.fault}, nil
	}
	return nil, err
}

type writerFaultConn struct {
	net.Conn
	fault *writerReplyFault
}

func (c *writerFaultConn) Write(p []byte) (int, error) {
	if c.fault.armed.Load() && c.fault.committed() && c.fault.drop.Swap(false) {
		c.fault.dropped.Store(true)
		c.fault.armed.Store(false)
		_ = c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(p)
}

type writerReplyFault struct {
	armed    atomic.Bool
	drop     atomic.Bool
	dropped  atomic.Bool
	accepted atomic.Int64
	backend  *appstoreanchorledger.Backend
	grant    appstoreanchorcore.Grant
	target   appstoreanchorstate.State
	reader   *appstoreanchortls.Client
}

func (f *writerReplyFault) committed() bool {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return false
	}
	request, err := appstoreanchorrequest.NewRead(f.grant.StoreID(), id)
	if err != nil {
		return false
	}
	coreRequest, err := appstoreanchorcore.Parse(request.Bytes(), f.grant.StoreID())
	if err != nil {
		return false
	}
	result, err := f.backend.Execute(coreRequest, f.grant)
	if err != nil {
		return false
	}
	unsigned, err := result.Unsigned()
	if err != nil {
		return false
	}
	state, err := appstoreanchorstate.Parse(unsigned[64:256], f.grant.StoreID())
	return err == nil && state.Bytes() == f.target.Bytes()
}

func writerFixtureWithFault(t *testing.T, role appstoreanchorcore.Role) (*appstoreanchortls.Writer, *appstoreanchorledger.Backend, *appstorefile.Directory, appstoreheader.Header, [32]byte, *writerReplyFault) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux durable service required")
	}
	h := header(t)
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
	fault := &writerReplyFault{}
	wrappedListener := &writerFaultListener{Listener: listener, fault: fault}
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
	fault.reader = readClient
	if role == appstoreanchorcore.Reader {
		return makeWriter(readerCert), backend, directory, h, sha256.Sum256(readerCert.Certificate[0]), fault
	}
	fault.backend = backend
	fault.grant, _ = appstoreanchorcore.NewGrant(h.StoreID(), sha256.Sum256(writerCert.Certificate[0]), appstoreanchorcore.Writer)
	return genesisWriter, backend, directory, h, sha256.Sum256(writerCert.Certificate[0]), fault
}

func TestWriterMutateReconcilesLostReplyBeforeRetry(t *testing.T) {
	transport, _, _, h, _, fault := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	genesis, err := appstoreanchorstate.Genesis(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	var snapshotID, transactionID [16]byte
	snapshotID[0], transactionID[0] = 11, 12
	entry, err := appstorejournal.NewEntry(0, snapshotID, transactionID)
	if err != nil {
		t.Fatal(err)
	}
	request, err := appstoreanchorrequest.PlanReservation(genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	proposed, ok := request.ProposedState()
	if !ok {
		t.Fatal("reservation has no proposed state")
	}
	fault.target = proposed
	fault.drop.Store(true)
	fault.armed.Store(true)
	before := fault.accepted.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := writerMutate(ctx, transport, request, genesis)
	if err != nil {
		t.Fatalf("lost-reply reconciliation failed: %v", err)
	}
	if result != proposed {
		t.Fatal("lost-reply reconciliation returned unexpected state")
	}
	if delta := fault.accepted.Load() - before; delta != 2 {
		t.Fatalf("accepted connections: %d, want 2", delta)
	}
	if !fault.dropped.Load() {
		t.Fatal("service response was not dropped after durable mutation")
	}
	actual, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, present := actual.State()
	if !present || state.Sequence() != 0 || state.JournalCount() != 1 || actual.ServiceVersion() != 1 || state != proposed {
		t.Fatal("anchor does not match committed proposal")
	}
	if fault.armed.Load() {
		t.Fatal("fault remained armed after response drop")
	}
}

func TestWriterScopedPayloadRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic scoped writer fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	payloads := [][]byte{make([]byte, 17), make([]byte, appstoreheader.ChunkSize+31)}
	for i := range payloads {
		for j := range payloads[i] {
			payloads[i][j] = byte((i+7)*31 + j%251)
		}
	}
	objects := make([]SnapshotObject, 2)
	for i, p := range payloads {
		f, e := os.CreateTemp(t.TempDir(), "source-")
		if e != nil {
			t.Fatal(e)
		}
		if e = f.Chmod(0600); e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(p); e != nil {
			t.Fatal(e)
		}
		if _, e = f.Seek(0, io.SeekStart); e != nil {
			t.Fatal(e)
		}
		var id [16]byte
		id[15] = byte(i + 1)
		objects[i] = SnapshotObject{ObjectID: id, MediaType: "text/plain", Source: f}
		defer f.Close()
	}
	w, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := w.Write(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}
	if commit.State.Sequence() != 1 {
		t.Fatalf("sequence: %d", commit.State.Sequence())
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	stateReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	anchor, present := stateReply.State()
	if !present || anchor != commit.State {
		t.Fatal("anchor differs from commit")
	}
	f, err := tx.OpenSnapshot(commit.State.CommittedSnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	check, err := master.CheckSnapshot(ctx, f, ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash})
	closeErr := f.Close()
	if err != nil || closeErr != nil || !check.Valid() {
		t.Fatalf("snapshot check: %v", err)
	}
	entries := check.Catalog().Entries()
	if len(entries) != 2 {
		t.Fatalf("catalog entries: %d", len(entries))
	}
	for i, ent := range entries {
		if ent.ObjectID() != objects[i].ObjectID || ent.Length() != uint64(len(payloads[i])) {
			t.Fatalf("catalog entry %d", i)
		}
	}
	if len(commit.Refs) != 2 {
		t.Fatalf("refs: %d", len(commit.Refs))
	}
	for i, ref := range commit.Refs {
		if ref.ObjectID() != objects[i].ObjectID {
			t.Fatalf("ref %d", i)
		}
	}
	encoded, err := tx.OpenSnapshot(commit.State.CommittedSnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	defer encoded.Close()
	var raw [appstoreheader.Size]byte
	if _, err = io.ReadFull(encoded, raw[:]); err != nil {
		t.Fatal(err)
	}
	encodedHeader, err := appstoreheader.Parse(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	var payloadOffset uint64
	for index := uint32(0); index < encodedHeader.ChunkCount(); index++ {
		var prefix [12]byte
		if _, err = io.ReadFull(encoded, prefix[:]); err != nil {
			t.Fatal(err)
		}
		gotIndex, n, sealedN := binary.BigEndian.Uint32(prefix[:4]), binary.BigEndian.Uint32(prefix[4:8]), binary.BigEndian.Uint32(prefix[8:])
		if gotIndex != index || sealedN != n+16000 {
			t.Fatal("encoded record prefix")
		}
		sealed := make([]byte, sealedN)
		if _, err = io.ReadFull(encoded, sealed); err != nil {
			t.Fatal(err)
		}
		plain, e := master.openRecord(ctx, encodedHeader, index, false, sealed)
		clear(sealed)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(plain)
		start := uint64(0)
		if index == 0 {
			start = 1048576
		}
		for pos := start; pos < uint64(len(plain)); pos++ {
			global := payloadOffset + pos - start
			var source int
			var local uint64
			if global < uint64(len(payloads[0])) {
				source, local = 0, global
			} else {
				source, local = 1, global-uint64(len(payloads[0]))
			}
			if global >= uint64(len(payloads[0])+len(payloads[1])) || plain[pos] != payloads[source][local] {
				t.Fatal("decoded payload differs")
			}
		}
		payloadOffset += uint64(len(plain)) - start
	}
	if payloadOffset != uint64(len(payloads[0])+len(payloads[1])) {
		t.Fatal("payload length")
	}
}

func TestWriterScopedRejectedTerminal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Reader)
	master, err := derive(ctx, h, []byte("synthetic rejected writer fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	w, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(ctx, nil); !errors.Is(err, ErrWriterRejected) {
		t.Fatalf("rejection: %v", err)
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	anchorReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, present := anchorReply.State()
	if !present {
		t.Fatal("anchor state is absent")
	}
	if state.Sequence() != 0 {
		t.Fatalf("anchor sequence: %d", state.Sequence())
	}
	journal, err := tx.Journal()
	if err != nil {
		t.Fatal(err)
	}
	journalStat, err := appstorefile.Stat(journal)
	closeErr := journal.Close()
	if err != nil || closeErr != nil || journalStat.Size != 40 {
		t.Fatalf("journal size: %d, %v", journalStat.Size, err)
	}
}

func TestWriterScopedCanceledAndBusy(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelCtx()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic cancel writer fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	w, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = w.Write(cancelled, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(ctx, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy: %v", err)
	}
	if _, err = w.Recover(ctx); !errors.Is(err, ErrBusy) {
		t.Fatalf("recovery busy: %v", err)
	}
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
}
