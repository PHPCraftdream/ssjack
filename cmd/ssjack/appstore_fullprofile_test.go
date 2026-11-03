package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorhttp"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
)

func TestAppstoreFullProfileCLI(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("set SSJACK_TEST_FULL_KDF=1 for full-profile CLI acceptance")
	}
	appstoreCLIAcceptance(t)
}

func appstoreCLIAcceptance(t *testing.T) {
	if !appstoreentry.Supported() {
		t.Skip("appstore unsupported on this platform")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	storeID := [16]byte{1}
	ledgerPath := t.TempDir()
	if err := os.Chmod(ledgerPath, 0700); err != nil {
		t.Fatal(err)
	}
	ledgerRoot, err := os.Open(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := appstoreanchorledger.New(ledgerRoot, storeID, 64)
	_ = ledgerRoot.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	now := time.Now()
	caKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, 32))
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	makeLeaf := func(seed byte, usage x509.ExtKeyUsage) tls.Certificate {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(seed)), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	serverCert, clientCert := makeLeaf(42, x509.ExtKeyUsageServerAuth), makeLeaf(43, x509.ExtKeyUsageClientAuth)
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, 32))
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service, err := appstoreanchorhttp.New(appstoreanchorhttp.Config{Authority: listen.Addr().String(), Certificate: serverCert, ClientCAs: roots, SigningKey: signer, Bindings: []appstoreanchorhttp.Binding{{CredentialID: sha256.Sum256(clientCert.Certificate[0]), StoreID: storeID, Role: appstoreanchorcore.Writer, Backend: backend}}})
	if err != nil {
		_ = listen.Close()
		t.Fatal(err)
	}
	svcCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(svcCtx, listen) }()
	t.Cleanup(func() { stop(); _ = listen.Close(); _ = service.Close(); <-done })
	endpoint := "https://" + listen.Addr().String() + "/anchor"
	transport, err := appstoreanchortls.NewWriter(appstoreanchortls.Config{Endpoint: endpoint, RootCAs: roots, Certificate: clientCert, ServiceKey: signer.Public().(ed25519.PublicKey), StoreID: storeID})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	create, err := appstoreanchorrequest.NewCreate(storeID)
	if err != nil {
		t.Fatal(err)
	}
	genesis, stopGenesis := context.WithTimeout(ctx, 30*time.Second)
	defer stopGenesis()
	reply, _, err := transport.Submit(genesis, create)
	if err != nil || reply.Outcome() != appstoreanchorreply.Committed {
		t.Fatalf("preprovision genesis: %v", err)
	}
	clientDER, err := x509.MarshalPKCS8PrivateKey(clientCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	storeDir := filepath.Join(t.TempDir(), "install")
	if err = os.Mkdir(storeDir, 0700); err != nil {
		t.Fatal(err)
	}
	master, secret := "synthetic full-profile master phrase", "synthetic full-profile secret"
	pub := clientCert.Certificate[0]
	input := []string{endpoint, endpoint, hex.EncodeToString(storeID[:]), hex.EncodeToString(storeID[:]), base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(caDER), base64.StdEncoding.EncodeToString(pub) + "," + base64.StdEncoding.EncodeToString(caDER), hex.EncodeToString(sha256Bytes(caDER)), hex.EncodeToString(sha256Bytes(pub)), base64.StdEncoding.EncodeToString(clientDER), master, master}
	prior := appstoreReadInput
	defer func() { appstoreReadInput = prior }()
	cursor := 0
	appstoreReadInput = func(string, bool) ([]byte, error) {
		if cursor >= len(input) {
			t.Fatal("unexpected setup prompt")
			return nil, nil
		}
		v := []byte(input[cursor])
		cursor++
		return v, nil
	}
	out, setupStderr, setupCode, setupErr := captureAppstoreOutput(t, func() (int, error) { return run(ctx, []string{"appstore", "setup", storeDir}) })
	if setupErr != nil || setupCode != 0 || cursor != len(input) {
		t.Fatalf("setup failed (%d prompts): %v", cursor, setupErr)
	}
	assertNoAppstoreSecrets(t, out+setupStderr, master, secret, string(clientDER), base64.StdEncoding.EncodeToString(clientDER))
	putInput := [][]byte{[]byte(master), []byte(secret)}
	cursor = 0
	appstoreReadInput = func(string, bool) ([]byte, error) {
		if cursor >= len(putInput) {
			t.Fatal("unexpected put prompt")
			return nil, nil
		}
		v := append([]byte(nil), putInput[cursor]...)
		cursor++
		return v, nil
	}
	stdout, stderr, code, putErr := captureAppstoreOutput(t, func() (int, error) { return run(ctx, []string{"appstore", "put", storeDir}) })
	if putErr != nil || code != 0 || cursor != 2 {
		t.Fatalf("put failed/prompts=%d: %v", cursor, putErr)
	}
	assertNoAppstoreSecrets(t, stdout+stderr, master, secret, string(clientDER), base64.StdEncoding.EncodeToString(clientDER))
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "{") || lines[1] != "sequence=1 revision=1" {
		t.Fatalf("unexpected safe CLI result: %q", stdout)
	}
	ref, err := appstoreplaceholder.Parse([]byte(lines[0]))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, ok := anchor.State()
	if !ok || state.Sequence() != 1 || state.JournalCount() != 1 {
		t.Fatal("anchor did not commit exactly one first entry")
	}
	root, err := os.Open(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := appstorefile.Open(root, storeID)
	_ = root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	tx, err := dir.Lock()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := tx.OpenSnapshot(state.CommittedSnapshotID())
	if err != nil {
		_ = tx.Close()
		t.Fatal(err)
	}
	gotHash, err := appstorefile.Hash(ctx, snapshot, 1<<30)
	if err != nil || gotHash != state.CommittedFileHash() {
		_ = snapshot.Close()
		_ = tx.Close()
		t.Fatalf("snapshot hash differs from authority: %v", err)
	}
	encoded, _, err := func() ([]byte, [32]byte, error) {
		st, e := appstoreentry.Open(storeDir)
		if e != nil {
			return nil, [32]byte{}, e
		}
		defer st.Close()
		return st.Load()
	}()
	if err != nil {
		_ = snapshot.Close()
		_ = tx.Close()
		t.Fatal(err)
	}
	installed, err := appstorecrypto.UnlockInstallation(ctx, encoded, []byte(master))
	clear(encoded)
	if err != nil {
		_ = snapshot.Close()
		_ = tx.Close()
		t.Fatal(err)
	}
	defer installed.Close()
	if _, err = snapshot.Seek(0, 0); err != nil {
		_ = snapshot.Close()
		_ = tx.Close()
		t.Fatal(err)
	}
	check, err := installed.CheckSnapshot(ctx, snapshot, appstorecrypto.ExpectedSnapshot{StoreID: storeID, SnapshotID: state.CommittedSnapshotID(), EncodedHash: gotHash})
	if err != nil {
		_ = snapshot.Close()
		_ = tx.Close()
		t.Fatal(err)
	}
	entries := check.Catalog().Entries()
	if len(entries) != 1 || entries[0].Length() != uint64(len(secret)) || ref.StoreID() != storeID || ref.SnapshotID() != state.CommittedSnapshotID() || entries[0].ObjectID() != ref.ObjectID() || entries[0].VersionID() != ref.VersionID() {
		_ = snapshot.Close()
		_ = tx.Close()
		t.Fatal("catalog does not map exact CLI reference to expected secret record")
	}
	_ = snapshot.Close()
	_ = tx.Close()
	cursor = 0
	appstoreReadInput = func(string, bool) ([]byte, error) {
		if cursor > 0 {
			t.Fatal("repeat put prompted for secret")
		}
		cursor++
		return []byte(master), nil
	}
	repeatOut, repeatStderr, repeatCode, repeatErr := captureAppstoreOutput(t, func() (int, error) { return run(ctx, []string{"appstore", "put", storeDir}) })
	assertNoAppstoreSecrets(t, repeatOut+repeatStderr, master, secret, string(clientDER), base64.StdEncoding.EncodeToString(clientDER))
	if repeatErr == nil && repeatCode == 0 || cursor != 1 {
		t.Fatal("repeat first-entry put did not refuse before secret prompt")
	}
}

func sha256Bytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func assertNoAppstoreSecrets(t *testing.T, output string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(output, secret) {
			t.Fatal("CLI disclosed private input")
		}
	}
}

func captureAppstoreOutput(t *testing.T, runFn func() (int, error)) (stdout, stderr string, code int, err error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	outR, outW, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	errR, errW, e := os.Pipe()
	if e != nil {
		_ = outR.Close()
		_ = outW.Close()
		t.Fatal(e)
	}
	restored := false
	restore := func() {
		if !restored {
			os.Stdout, os.Stderr = oldOut, oldErr
			restored = true
		}
	}
	t.Cleanup(restore)
	os.Stdout = outW
	os.Stderr = errW
	code, err = runFn()
	_ = outW.Close()
	_ = errW.Close()
	restore()
	var outBuffer, errBuffer bytes.Buffer
	_, _ = outBuffer.ReadFrom(outR)
	_, _ = errBuffer.ReadFrom(errR)
	_ = outR.Close()
	_ = errR.Close()
	return outBuffer.String(), errBuffer.String(), code, err
}
