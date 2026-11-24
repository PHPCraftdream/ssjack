package ownertest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ktav-lang/golang/pure"
	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const nativeArchiveMaster = "synthetic native archive installation password"
const nativeArchivePassword = "synthetic native archive vault password"
const nativeArchiveValue = "synthetic native selected private application value"
const nativeArchiveExcluded = "synthetic native excluded global application value"
const nativeArchiveCredential = "synthetic native selected SSH credential"
const nativeArchiveMCPBasic = "synthetic native MCP basic credential"
const nativeArchiveMCPBearer = "synthetic-native-mcp-bearer-credential"
const nativeArchiveMCPHeader = "synthetic native MCP custom header credential"
const nativeArchiveMCPBearerHeader = "synthetic native MCP bearer header credential"
const nativeArchiveMCPExcluded = "synthetic-native-excluded-mcp-credential"
const nativeArchiveMCPExcludedHeader = "synthetic native excluded MCP header credential"

func nativeArchiveMust(t nativeKeeperReporter, err error) {
	t.Helper()
	if err != nil {
		t.Fatal("native archive fixture operation failed")
	}
}

// importBytes and importDigest are the original owneracceptance test helpers,
// copied so the native archive suite can diff ciphertext without importing the
// acceptance package.
func importBytes(t nativeKeeperReporter, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("native archive fixture operation failed")
	}
	return data
}
func importDigest(t nativeKeeperReporter, path string) [32]byte {
	return sha256.Sum256(importBytes(t, path))
}

// The test authority is volatile. It tests native clients, not durable service storage.
func nativeArchiveAuthority(t *testing.T, header appstoreheader.Header, dev, ino uint64) appstorecrypto.Binding {
	t.Helper()
	now := time.Now()
	caKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	nativeArchiveMust(t, err)
	ca, err := x509.ParseCertificate(caDER)
	nativeArchiveMust(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(seed byte, usage x509.ExtKeyUsage) tls.Certificate {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(seed)), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		nativeArchiveMust(t, err)
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	serverCert, clientCert := leaf(92, x509.ExtKeyUsageServerAuth), leaf(93, x509.ExtKeyUsageClientAuth)
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{94}, 32))
	credential := sha256.Sum256(clientCert.Certificate[0])
	grant, err := appstoreanchorcore.NewGrant(header.StoreID(), credential, appstoreanchorcore.Writer)
	nativeArchiveMust(t, err)
	current, err := appstoreanchorcore.Missing(header.StoreID())
	nativeArchiveMust(t, err)
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/anchor" || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || sha256.Sum256(r.TLS.PeerCertificates[0].Raw) != credential || r.Header.Get("Content-Type") != "application/octet-stream" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 305))
		if err != nil || len(raw) > 304 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		request, err := appstoreanchorcore.Parse(raw, header.StoreID())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		result, err := appstoreanchorcore.Evaluate(request, grant, current)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		unsigned, err := result.Unsigned()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if next, ok := result.Next(); ok {
			current = next
		}
		signature := ed25519.Sign(signer, unsigned[:])
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(append(unsigned[:], signature...))
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientCert.PrivateKey)
	if err != nil {
		server.Close()
		t.Fatal("native archive fixture operation failed")
	}
	t.Cleanup(func() { server.Close(); clear(privateDER); clear(signer) })
	return appstorecrypto.Binding{Endpoint: server.URL + "/anchor", RootsDER: [][]byte{caDER}, CertificateDER: clientCert.Certificate, PrivateDER: privateDER, ServiceKey: signer.Public().(ed25519.PublicKey), Header: header, DirectoryDev: dev, DirectoryIno: ino}
}

func nativeArchiveInstallation(t *testing.T, ctx context.Context) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "installation")
	root, err := ownerfs.MakeRoot(path)
	nativeArchiveMust(t, err)
	nativeArchiveMust(t, root.Close())
	store, err := appstoreentry.Open(path)
	nativeArchiveMust(t, err)
	defer store.Close()
	dev, ino, err := store.Identity()
	nativeArchiveMust(t, err)
	var raw [appstoreheader.Size]byte
	copy(raw[:8], "SSAPP001")
	binary.BigEndian.PutUint16(raw[8:10], 1)
	_, err = rand.Read(raw[12:44])
	nativeArchiveMust(t, err)
	binary.BigEndian.PutUint32(raw[60:64], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint64(raw[64:72], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint32(raw[72:76], 1)
	_, err = rand.Read(raw[80:])
	nativeArchiveMust(t, err)
	header, err := appstoreheader.Parse(raw[:])
	nativeArchiveMust(t, err)
	binding := nativeArchiveAuthority(t, header, dev, ino)
	master := []byte(nativeArchiveMaster)
	defer clear(master)
	encoded, err := appstorecrypto.NewInstallation(ctx, header, master, binding)
	nativeArchiveMust(t, err)
	defer clear(encoded)
	nativeArchiveMust(t, store.Install(encoded))
	installation, err := appstorecrypto.UnlockInstallation(ctx, encoded, master)
	nativeArchiveMust(t, err)
	defer installation.Close()
	file, err := store.Root()
	nativeArchiveMust(t, err)
	directory, err := appstorefile.Open(file, header.StoreID())
	nativeArchiveMust(t, file.Close())
	nativeArchiveMust(t, err)
	defer directory.Close()
	_, transport, err := installation.Writer(directory)
	nativeArchiveMust(t, err)
	defer transport.Close()
	create, err := appstoreanchorrequest.NewCreate(header.StoreID())
	nativeArchiveMust(t, err)
	reply, _, err := transport.Submit(ctx, create)
	nativeArchiveMust(t, err)
	if reply.Outcome() != appstoreanchorreply.Committed {
		t.Fatal("native archive installation genesis did not commit")
	}
	id := header.StoreID()
	return path, hex.EncodeToString(id[:])
}

func nativeArchiveDatabase(t *testing.T, ctx context.Context, store, id string, seeded bool) (*ownercontrol.Control, string, string) {
	t.Helper()
	v := vault.NewDirectory()
	defer v.Close()
	server := ""
	if seeded {
		key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		defer clear(key)
		pin, err := ssh.NewPublicKey(key.Public())
		nativeArchiveMust(t, err)
		target := vault.Target{Address: "archive.invalid:22", User: "selected-user", Password: []byte(nativeArchiveCredential), HostKeys: []string{string(ssh.MarshalAuthorizedKey(pin))}, Usage: "agent"}
		defer clear(target.Password)
		server, err = v.AddServer("archive-source", "selected", target)
		nativeArchiveMust(t, err)
		profile, err := v.AccountProfile(server, "selected")
		nativeArchiveMust(t, err)
		nativeArchiveMCPDirectory(t, v, profile)
		target.User = "excluded-user"
		nativeArchiveMust(t, v.SetAccount(server, "excluded", target))
	}
	master := []byte(nativeArchiveMaster)
	defer clear(master)
	nativeArchiveMust(t, v.LinkOwnerStore(vault.OwnerStore{Directory: store, StoreID: id, Master: master}))
	password := []byte(nativeArchivePassword)
	defer clear(password)
	path := filepath.Join(t.TempDir(), "archive.ktav")
	nativeArchiveMust(t, vault.CreateWithRecords(ctx, path, v, password))
	control, err := ownercontrol.Open(ctx, path, password)
	nativeArchiveMust(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := control.Close(cleanup); err != nil {
			t.Error("native archive coordinator did not close")
		}
	})
	return control, path, server
}

func nativeArchiveMCPDirectory(t *testing.T, v *vault.Vault, profile string) {
	t.Helper()
	directory := mcpdirectory.New()
	server, err := directory.AddServer("archive-mcp", "https://archive.invalid/mcp")
	nativeArchiveMust(t, err)
	accounts := []mcpdirectory.Account{
		{ServerID: server, Name: "public", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "none"}},
		{ServerID: server, Name: "basic", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "basic", Username: "synthetic-mcp-user", Secret: []byte(nativeArchiveMCPBasic)}, Headers: []mcpdirectory.Header{{Name: "X-Archive-Key", Value: []byte(nativeArchiveMCPHeader)}}},
		{ServerID: server, Name: "bearer", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte(nativeArchiveMCPBearer)}, Headers: []mcpdirectory.Header{{Name: "X-Bearer-Key", Value: []byte(nativeArchiveMCPBearerHeader)}}},
		{ServerID: server, Name: "not-selected", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "none"}},
	}
	var last []mcpdirectory.Binding
	for i := range accounts {
		id, err := directory.AddAccount(accounts[i])
		nativeArchiveMust(t, err)
		stored := directory.Accounts[id]
		if accounts[i].Name != "not-selected" {
			last = append(last, mcpdirectory.Binding{ServerID: server, AccountID: id, ServerRevision: directory.Servers[server].Revision, AccountRevision: stored.Revision})
		}
		accounts[i].Clear()
	}
	excludedServer, err := directory.AddServer("archive-excluded", "https://excluded.invalid/mcp")
	nativeArchiveMust(t, err)
	excludedAccount := mcpdirectory.Account{ServerID: excludedServer, Name: "excluded", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte(nativeArchiveMCPExcluded)}, Headers: []mcpdirectory.Header{{Name: "X-Excluded-Key", Value: []byte(nativeArchiveMCPExcludedHeader)}}}
	_, err = directory.AddAccount(excludedAccount)
	excludedAccount.Clear()
	nativeArchiveMust(t, err)
	directory.Last[profile] = last
	v.RemoteMCP = directory
}

type nativeArchiveInput struct {
	stage  string
	marker string
	value  []byte
}

func nativeArchiveCommand(t *testing.T, ctx context.Context, database, label string, cancelled bool, arguments []string, steps ...nativeArchiveInput) *nativeTerminalTrace {
	t.Helper()
	lifetime, cancel := context.WithTimeout(ctx, 170*time.Second)
	defer cancel()
	defer func() {
		for _, step := range steps {
			clear(step.value)
		}
	}()
	executable, err := os.Executable()
	nativeArchiveMust(t, err)
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	nativeArchiveMust(t, err)
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
			environment = append(environment, entry)
		}
	}
	decision := "0"
	if cancelled {
		decision = "1"
	}
	environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_NATIVE_CHILD=1", "SSJACK_OWNER_COMMAND_CHILD=1", "SSJACK_OWNER_COMMAND_CANCEL="+decision)
	args := append([]string{"-test.run=^TestOwnerNativeCommandChild$", "--", "--vault", database, "owner"}, arguments...)
	trace := startNativeTerminal(t, t, lifetime, label, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Environment: environment, Args: args})
	trace.addOwnerCommandChildFailureMarkers()
	defer func() {
		trace.cleanup(t, "", "native archive terminal output did not join")
		for _, private := range []struct{ class, value string }{
			{"vault-password", nativeArchivePassword},
			{"installation-password", nativeArchiveMaster},
			{"selected-value", nativeArchiveValue},
			{"excluded-value", nativeArchiveExcluded},
			{"ssh-credential", nativeArchiveCredential},
			{"mcp-basic", nativeArchiveMCPBasic},
			{"mcp-bearer", nativeArchiveMCPBearer},
			{"mcp-basic-header", nativeArchiveMCPHeader},
			{"mcp-bearer-header", nativeArchiveMCPBearerHeader},
			{"mcp-excluded-credential", nativeArchiveMCPExcluded},
			{"mcp-excluded-header", nativeArchiveMCPExcludedHeader},
		} {
			if trace.capture.Contains([]byte(private.value)) {
				trace.flowFail()
				t.Errorf("native archive terminal disclosed private data (class=%s)", private.class)
			}
		}
	}()
	ending := byte('\n')
	if runtime.GOOS == "windows" {
		ending = '\r'
	}
	trace.expectText(t, lifetime, "vault-unlock", "Vault secret:", "native archive command missed terminal barrier")
	trace.write(t, "vault-unlock", append([]byte(nativeArchivePassword), ending))
	for _, step := range steps {
		trace.expectText(t, lifetime, step.stage, step.marker, "native archive command missed terminal barrier")
		secretField := step.marker == "Value:" || step.marker == "Archive password:"
		if secretField {
			trace.write(t, step.stage+"-open-secret-prompt", []byte{'\r'})
			trace.expectText(t, lifetime, step.stage+"-secret-prompt", "Secret (hidden; Enter submits, Esc/Ctrl+C cancels):", "native archive command did not open the hidden secret prompt")
			if len(step.value) == 1 && step.value[0] == '\x1b' {
				trace.write(t, step.stage+"-cancel-secret-prompt", []byte{'\x1b'})
				continue
			}
			input := append(bytes.Clone(step.value), '\r')
			trace.write(t, step.stage+"-secret-value", input)
			trace.expectText(t, lifetime, step.stage+"-secret-entered", step.marker+" <hidden; entered>", "native archive command did not display the entered secret field")
			trace.write(t, step.stage+"-apply-secret", []byte{'\t', '\r'})
			continue
		}
		if len(step.value) != 0 {
			nativeArchiveWriteKeys(t, trace, lifetime, step.stage, step.value)
		}
	}
	if cancelled {
		trace.wait(t, lifetime, "native archive command did not complete cancellation")
	} else {
		trace.wait(t, lifetime, "native archive command did not complete confirmation")
		trace.expectText(t, lifetime, "persistence-receipt", "Owner command completed; encrypted persistence confirmed.", "native archive command omitted its persistence receipt")
	}
	return trace
}

// nativeArchiveWriteKeys delivers one key byte per terminal write and waits
// for the child's repaint (capture growth) after each key, so the plain-text
// form input path never receives a burst the vulnerable bubbletea reader can
// lose or reorder. Stage names carry only static indexes, never key bytes.
func nativeArchiveWriteKeys(t *testing.T, trace *nativeTerminalTrace, ctx context.Context, stage string, value []byte) {
	t.Helper()
	for index, key := range value {
		keyStage := fmt.Sprintf("%s-key-%d-of-%d", stage, index+1, len(value))
		offset := 0
		trace.capture.Inspect(func(data []byte, _ int, _ bool) { offset = len(data) })
		trace.write(t, keyStage, []byte{key})
		trace.expect(t, ctx, keyStage, "native archive command did not repaint after the key", func(data []byte) bool {
			return len(data) > offset
		})
	}
}

func nativeArchiveCheckpoint(t *testing.T, trace *nativeTerminalTrace, stage, failure string, err error) {
	class := nativeResultClass(err, "endpoint-error")
	trace.recordCaptured(stage, "result", "class=%s ", class)
	if err != nil {
		trace.report(t).Fatalf("%s (%s)", failure, class)
	}
}

func nativeArchiveApply(value string) []byte {
	return append([]byte(value), '\t', '\r')
}

func TestVaultOwnerArchiveFullProfile(t *testing.T) {
	flakediag.Begin(t)
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production native archive process acceptance is CI-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	store, id := nativeArchiveInstallation(t, ctx)
	control, database, server := nativeArchiveDatabase(t, ctx, store, id, true)
	mcpServerID, mcpAccounts := nativeArchiveMCPSelection(t, control)
	before := importBytes(t, database)
	secretArgs := []string{"add-secret", "--scope", "server", "--server", "archive-source", "--name", "selected-value"}
	cancelTrace := nativeArchiveCommand(t, ctx, database, "native archive add server value cancel", true, secretArgs, nativeArchiveInput{"value-form", "Value:", []byte("\x1b")})
	cancelReporter := cancelTrace.report(t)
	if !bytes.Equal(before, importBytes(cancelReporter, database)) {
		cancelReporter.Fatal("cancelled native value form changed ciphertext")
	}
	cancelTrace.flow.Complete()
	serverApplyTrace := nativeArchiveCommand(t, ctx, database, "native archive add server value apply", false, secretArgs, nativeArchiveInput{"value-form", "Value:", []byte(nativeArchiveValue)})
	serverApplyTrace.flow.Complete()
	globalApplyTrace := nativeArchiveCommand(t, ctx, database, "native archive add global value apply", false, []string{"add-secret", "--scope", "global", "--name", "excluded-value"}, nativeArchiveInput{"value-form", "Value:", []byte(nativeArchiveExcluded)})
	globalApplyTrace.flow.Complete()
	applyReporter := serverApplyTrace.report(t)
	valueVerifyTrace := newNativeTerminalTrace(t, "shared native archive value verification")
	valueVerifyReporter := valueVerifyTrace.report(t)
	valueVerifyTrace.recordCaptured("source-database-status", "check", "")
	status := control.Backend().Status()
	if status.Database.Err != nil {
		valueVerifyReporter.Fatal("native value helper left a parent database error")
	}
	if status.Database.Revision != status.Database.SavedRevision {
		valueVerifyReporter.Fatal("native value helper did not update the parent saved state")
	}
	valueVerifyTrace.recordCaptured("source-vault-load", "attempt", "")
	loaded, err := vault.Load(database, []byte(nativeArchivePassword))
	if err != nil {
		valueVerifyReporter.Fatal("native archive source vault load failed")
	}
	valueVerifyTrace.flow.Complete()
	alias, reference := "", ""
	for key, binding := range loaded.Secrets {
		if binding.ServerID == server {
			alias, reference = key, binding.Ref
		}
	}
	loaded.Close()
	if alias == "" {
		applyReporter.Fatal("native value helper did not persist its server scope")
	}
	exportVerifyTrace := newNativeTerminalTrace(t, "shared native archive export verification")
	exportReporter := exportVerifyTrace.report(t)
	exportVerifyTrace.recordCaptured("source-ciphertext-baseline", "attempt", "")
	beforeExport := importBytes(exportReporter, database)
	archives := make(map[string]string)
	for _, format := range []string{"encrypted", "plaintext"} {
		archive := filepath.Join(t.TempDir(), "selected.zip")
		arguments := []string{"export", "--scope", "account", "--server", "archive-source", "--account", "selected", "--mcp-accounts", strings.Join([]string{mcpAccounts["public"], mcpAccounts["basic"], mcpAccounts["bearer"]}, ","), "--destination", archive, "--format", format}
		confirmation := ""
		label := "native archive export account encrypted apply"
		if format == "plaintext" {
			label = "native archive export account plaintext apply"
			confirmation = "EXPORT PLAINTEXT"
			plaintextCancelTrace := nativeArchiveCommand(t, ctx, database, "native archive export account plaintext cancel", true, arguments, nativeArchiveInput{"export-confirmation", "Confirmation:", []byte("\x1b")})
			plaintextCancelReporter := plaintextCancelTrace.report(t)
			if _, err := os.Lstat(archive); err == nil {
				plaintextCancelReporter.Fatal("cancelled native plaintext disclosure created an artifact")
			} else if !os.IsNotExist(err) {
				plaintextCancelReporter.Fatal("could not stat the cancelled native plaintext archive path")
			}
			plaintextCancelTrace.flow.Complete()
		}
		sourceTrace := nativeArchiveCommand(t, ctx, database, label, false, arguments, nativeArchiveInput{"export-confirmation", "Confirmation:", nativeArchiveApply(confirmation)})
		sourceFormatReporter := sourceTrace.report(t)
		verifyNativeArchive(sourceFormatReporter, ctx, archive, format == "encrypted", server, alias, mcpServerID, mcpAccounts)
		archives[format] = archive
		sourceTrace.flow.Complete()
	}
	exportVerifyTrace.recordCaptured("source-ciphertext-reread", "attempt", "")
	if !bytes.Equal(beforeExport, importBytes(exportReporter, database)) {
		exportReporter.Fatal("native selected export changed its source ciphertext")
	}
	exportVerifyTrace.recordCaptured("encrypted-baseline-digest", "attempt", "")
	archiveDigest := importDigest(exportReporter, archives["encrypted"])
	exportVerifyTrace.recordCaptured("source-endpoint-metadata", "attempt", "")
	_, err = control.Backend().Metadata()
	nativeArchiveCheckpoint(t, exportVerifyTrace, "source-endpoint-metadata", "native export helper detach closed its coordinator", err)
	exportVerifyTrace.recordCaptured("source-endpoint-close", "attempt", "")
	nativeArchiveCheckpoint(t, exportVerifyTrace, "source-endpoint-close", "native archive source coordinator did not close", control.Close(ctx))
	exportVerifyTrace.flow.Complete()
	destination, target, _ := nativeArchiveDatabase(t, ctx, store, id, false)
	importTrace := nativeArchiveCommand(t, ctx, target, "native archive import encrypted apply", false, []string{"import", "--file", archives["encrypted"]},
		nativeArchiveInput{"archive-unlock", "Archive password:", []byte(nativeArchivePassword)},
		nativeArchiveInput{"import-preview-server", "MCP server \"archive-mcp\"", nil},
		nativeArchiveInput{"import-preview-account", "MCP account \"basic\"", nil},
		nativeArchiveInput{"import-confirm-action", "[Confirm import", []byte("\r")},
		nativeArchiveInput{"import-confirm-text", "Type IMPORT", nativeArchiveApply("IMPORT")})
	importReporter := importTrace.report(t)
	imported, err := vault.Load(target, []byte(nativeArchivePassword))
	if err != nil {
		importReporter.Fatal("native archive destination vault load failed")
	}
	defer imported.Close()
	if len(imported.Targets) != 1 {
		importReporter.Fatal("native import target count changed")
	}
	if len(imported.Secrets) != 1 {
		importReporter.Fatal("native import secret count changed")
	}
	if imported.Secrets[alias].ServerID != server {
		importReporter.Fatal("native import secret lost its server scope")
	}
	if imported.Secrets[alias].Ref == reference {
		importReporter.Fatal("native import reused the source publication")
	}
	if imported.OwnerStore == nil {
		importReporter.Fatal("native import lost its owner store link")
	}
	if imported.OwnerStore.StoreID != id {
		importReporter.Fatal("native import changed the owner store identity")
	}
	verifyNativeMCP(importReporter, imported, mcpServerID, mcpAccounts, true, true)
	profile, err := imported.AccountProfile(server, "selected")
	nativeArchiveMust(importReporter, err)
	if !bytes.Equal(imported.Targets[profile].Password, []byte(nativeArchiveCredential)) {
		importReporter.Fatal("native import lost the selected private credential")
	}
	importTrace.flow.Complete()
	readback := filepath.Join(t.TempDir(), "readback.zip")
	freshMCPServerID, freshMCPAccounts := nativeArchiveMCPSelection(t, destination)
	// Two TABs: the readback export passes no --mcp-accounts, so its MCP
	// accounts field is unsupplied and the first TAB lands there, not on Apply.
	readbackTrace := nativeArchiveCommand(t, ctx, target, "native archive export account plaintext readback", false, []string{"export", "--scope", "account", "--server", "archive-source", "--account", "selected", "--destination", readback, "--format", "plaintext"}, nativeArchiveInput{"export-confirmation", "Confirmation:", []byte("EXPORT PLAINTEXT\t\t\r")})
	readbackReporter := readbackTrace.report(t)
	verifyNativeArchive(readbackReporter, ctx, readback, false, server, alias, "", nil)
	readbackTrace.flow.Complete()
	beforeMCPOnly := importBytes(t, target)
	mcpOnly := filepath.Join(t.TempDir(), "mcp-only.zip")
	destinationTrace := nativeArchiveCommand(t, ctx, target, "native archive export MCP-only plaintext apply", false, []string{"export", "--scope", "mcp", "--mcp-accounts", strings.Join([]string{freshMCPAccounts["public"], freshMCPAccounts["basic"], freshMCPAccounts["bearer"]}, ","), "--destination", mcpOnly, "--format", "plaintext"}, nativeArchiveInput{"export-confirmation", "Confirmation:", nativeArchiveApply("EXPORT PLAINTEXT")})
	destinationReporter := destinationTrace.report(t)
	verifyNativeMCPOnlyArchive(destinationReporter, ctx, mcpOnly, freshMCPServerID, freshMCPAccounts)
	if !bytes.Equal(beforeMCPOnly, importBytes(t, target)) {
		destinationReporter.Fatal("native MCP-only export changed its source ciphertext")
	}
	if archiveDigest != importDigest(importReporter, archives["encrypted"]) {
		importReporter.Fatal("native import changed its source archive")
	}
	destinationTrace.recordCaptured("destination-endpoint-close", "attempt", "")
	nativeArchiveCheckpoint(t, destinationTrace, "destination-endpoint-close", "native archive destination coordinator did not close", destination.Close(ctx))
	destinationTrace.recordCaptured("destination-endpoint-reacquire", "attempt", "")
	role, err := ownerlocal.Listen(target)
	nativeArchiveCheckpoint(t, destinationTrace, "destination-endpoint-reacquire", "native archive destination endpoint was not reacquired", err)
	destinationTrace.recordCaptured("reacquired-endpoint-close", "attempt", "")
	nativeArchiveCheckpoint(t, destinationTrace, "reacquired-endpoint-close", "native archive reacquired endpoint did not close", role.Close())
	destinationTrace.flow.Complete()
}

func verifyNativeArchive(t nativeKeeperReporter, ctx context.Context, path string, encrypted bool, server, alias, mcpServerID string, mcpAccounts map[string]string) {
	t.Helper()
	var password []byte
	if encrypted {
		password = []byte(nativeArchivePassword)
		defer clear(password)
	}
	archive, err := ownerarchive.ReadFile(ctx, path, password)
	if err != nil {
		t.Fatal("native selected archive read failed")
	}
	defer archive.Close()
	if archive.Encrypted() != encrypted {
		t.Fatal("native archive changed encryption mode")
	}
	secretIDs := archive.SecretIDs()
	if len(secretIDs) != 1 {
		t.Fatal("native archive secret count changed")
	}
	if secretIDs[0] != alias {
		t.Fatal("native archive selected the wrong secret")
	}
	value, ok := archive.Value(alias)
	defer clear(value)
	if !ok {
		t.Fatal("native archive omitted the selected private value")
	}
	if !bytes.Equal(value, []byte(nativeArchiveValue)) {
		t.Fatal("native archive lost the exact private value")
	}
	data := archive.Database()
	defer clear(data)
	var selected vault.Vault
	if err := pure.LoadsInto(string(data), &selected); err != nil {
		t.Fatal("native archive database parse failed")
	}
	defer selected.Close()
	if selected.OwnerStore != nil {
		t.Fatal("native archive included the master link")
	}
	if len(selected.Servers) != 1 {
		t.Fatal("native archive server count changed")
	}
	if len(selected.Targets) != 1 {
		t.Fatal("native archive target count changed")
	}
	if len(selected.Secrets) != 1 {
		t.Fatal("native archive database secret count changed")
	}
	if len(selected.Servers[server].Accounts) != 1 {
		t.Fatal("native archive selected server account count changed")
	}
	if selected.Secrets[alias].ServerID != server {
		t.Fatal("native archive secret scope changed")
	}
	profile, err := selected.AccountProfile(server, "selected")
	nativeArchiveMust(t, err)
	if !bytes.Equal(selected.Targets[profile].Password, []byte(nativeArchiveCredential)) {
		t.Fatal("native archive changed its selected private credential")
	}
	if mcpServerID == "" {
		if selected.RemoteMCP != nil {
			t.Fatal("native archive included unselected MCP records")
		}
	} else {
		verifyNativeMCP(t, &selected, mcpServerID, mcpAccounts, false, true)
	}
}

func nativeArchiveMCPSelection(t *testing.T, control *ownercontrol.Control) (string, map[string]string) {
	t.Helper()
	metadata, err := control.Backend().Metadata()
	nativeArchiveMust(t, err)
	servers := make(map[string]string, len(metadata.RemoteMCP.Servers))
	for _, server := range metadata.RemoteMCP.Servers {
		servers[server.Name] = server.ID
	}
	accounts := make(map[string]string, len(metadata.RemoteMCP.Accounts))
	for _, account := range metadata.RemoteMCP.Accounts {
		if account.ServerID == servers["archive-mcp"] {
			accounts[account.Name] = account.ID
		}
	}
	if servers["archive-mcp"] == "" {
		t.Fatal("native MCP archive fixture server is missing")
	}
	if len(accounts) < 3 {
		t.Fatal("native MCP archive fixture has too few accounts")
	}
	return servers["archive-mcp"], accounts
}

func verifyNativeMCPOnlyArchive(t nativeKeeperReporter, ctx context.Context, path, sourceServerID string, sourceIDs map[string]string) {
	t.Helper()
	archive, err := ownerarchive.ReadFile(ctx, path, nil)
	if err != nil {
		t.Fatal("native MCP-only archive read failed")
	}
	defer archive.Close()
	if archive.Encrypted() {
		t.Fatal("native MCP-only archive changed encryption mode")
	}
	if len(archive.SecretIDs()) != 0 {
		t.Fatal("native MCP-only archive included private values")
	}
	data := archive.Database()
	defer clear(data)
	var selected vault.Vault
	if err := pure.LoadsInto(string(data), &selected); err != nil {
		t.Fatal("native archive database parse failed")
	}
	defer selected.Close()
	if selected.OwnerStore != nil {
		t.Fatal("native MCP-only archive included the master link")
	}
	if len(selected.Servers) != 0 {
		t.Fatal("native MCP-only archive included SSH servers")
	}
	if len(selected.Targets) != 0 {
		t.Fatal("native MCP-only archive included SSH targets")
	}
	if len(selected.Secrets) != 0 {
		t.Fatal("native MCP-only archive included application secret bindings")
	}
	verifyNativeMCP(t, &selected, sourceServerID, sourceIDs, false, false)
}

func verifyNativeMCP(t nativeKeeperReporter, selected *vault.Vault, sourceServerID string, sourceIDs map[string]string, freshIDs, expectLast bool) {
	t.Helper()
	if selected.RemoteMCP == nil {
		t.Fatal("native archive omitted the MCP directory")
	}
	if len(selected.RemoteMCP.Servers) != 1 {
		t.Fatal("native archive MCP server count changed")
	}
	if len(selected.RemoteMCP.Accounts) != 3 {
		t.Fatal("native archive MCP account count changed")
	}
	var serverID string
	for id, server := range selected.RemoteMCP.Servers {
		serverID = id
		if server.Name != "archive-mcp" {
			t.Fatal("native MCP server name changed")
		}
		if server.URL != "https://archive.invalid/mcp" {
			t.Fatal("native MCP server URL changed")
		}
		if server.Revision != 1 {
			t.Fatal("native MCP server revision changed")
		}
		if (id == sourceServerID) != !freshIDs {
			t.Fatal("native MCP server ID did not follow the publication mode")
		}
	}
	if serverID == "" {
		t.Fatal("native MCP server is missing")
	}
	seen := make(map[string]bool)
	for id, account := range selected.RemoteMCP.Accounts {
		if account.ServerID != serverID {
			t.Fatal("native MCP account server binding changed")
		}
		if account.Revision != 1 {
			t.Fatal("native MCP account revision changed")
		}
		if (id == sourceIDs[account.Name]) != !freshIDs {
			t.Fatal("native MCP account ID did not follow the publication mode")
		}
		seen[account.Name] = true
		switch account.Name {
		case "public":
			if account.Auth.Kind != "none" {
				t.Fatal("native public MCP authentication kind changed")
			}
			if len(account.Auth.Secret) != 0 {
				t.Fatal("native public MCP account acquired a credential")
			}
			if len(account.Headers) != 0 {
				t.Fatal("native public MCP account acquired headers")
			}
		case "basic":
			if account.Auth.Kind != "basic" {
				t.Fatal("native basic MCP authentication kind changed")
			}
			if account.Auth.Username != "synthetic-mcp-user" {
				t.Fatal("native basic MCP username changed")
			}
			if !bytes.Equal(account.Auth.Secret, []byte(nativeArchiveMCPBasic)) {
				t.Fatal("native basic MCP credential changed")
			}
			if len(account.Headers) != 1 {
				t.Fatal("native basic MCP header count changed")
			}
			if account.Headers[0].Name != "X-Archive-Key" {
				t.Fatal("native basic MCP header name changed")
			}
			if !bytes.Equal(account.Headers[0].Value, []byte(nativeArchiveMCPHeader)) {
				t.Fatal("native basic MCP header value changed")
			}
		case "not-selected":
			t.Fatal("native archive included an unselected MCP account")
		case "bearer":
			if account.Auth.Kind != "bearer" {
				t.Fatal("native bearer MCP authentication kind changed")
			}
			if !bytes.Equal(account.Auth.Secret, []byte(nativeArchiveMCPBearer)) {
				t.Fatal("native bearer MCP credential changed")
			}
			if len(account.Headers) != 1 {
				t.Fatal("native bearer MCP header count changed")
			}
			if account.Headers[0].Name != "X-Bearer-Key" {
				t.Fatal("native bearer MCP header name changed")
			}
			if !bytes.Equal(account.Headers[0].Value, []byte(nativeArchiveMCPBearerHeader)) {
				t.Fatal("native bearer MCP header value changed")
			}
		default:
			t.Fatal("native archive included an unselected MCP account")
		}
	}
	if !seen["public"] {
		t.Fatal("native MCP public account was omitted")
	}
	if !seen["basic"] {
		t.Fatal("native MCP basic account was omitted")
	}
	if !seen["bearer"] {
		t.Fatal("native MCP bearer account was omitted")
	}
	if expectLast {
		if len(selected.RemoteMCP.Last) != 1 {
			t.Fatal("native archive lost the selected MCP Last context")
		}
		for _, bindings := range selected.RemoteMCP.Last {
			if len(bindings) != 3 {
				t.Fatal("native MCP Last did not close over all selected enabled identities")
			}
			for _, binding := range bindings {
				account, ok := selected.RemoteMCP.Accounts[binding.AccountID]
				if !ok {
					t.Fatal("native MCP Last refers to a missing account")
				}
				if account.ServerID != binding.ServerID {
					t.Fatal("native MCP Last account server binding changed")
				}
				if selected.RemoteMCP.Servers[binding.ServerID].Revision != binding.ServerRevision {
					t.Fatal("native MCP Last server revision changed")
				}
				if account.Revision != binding.AccountRevision {
					t.Fatal("native MCP Last account revision changed")
				}
			}
		}
	} else if len(selected.RemoteMCP.Last) != 0 {
		t.Fatal("native MCP-only selection invented an SSH Last context")
	}
}
