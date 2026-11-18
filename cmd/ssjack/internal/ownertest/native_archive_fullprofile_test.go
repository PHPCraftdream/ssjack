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

func nativeArchiveMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// importBytes and importDigest are the original owneracceptance test helpers,
// copied so the native archive suite can diff ciphertext without importing the
// acceptance package.
func importBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func importDigest(t *testing.T, path string) [32]byte { return sha256.Sum256(importBytes(t, path)) }

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
		t.Fatal(err)
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
	marker string
	value  []byte
}

func nativeArchiveCommand(t *testing.T, ctx context.Context, database string, cancelled bool, arguments []string, steps ...nativeArchiveInput) {
	t.Helper()
	lifetime, cancel := context.WithTimeout(ctx, 170*time.Second)
	defer cancel()
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
	terminal, err := ownerterminal.Start(lifetime, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Environment: environment, Args: args})
	nativeArchiveMust(t, err)
	started := time.Now()
	tail := newOwnerChildTail()
	terminal.Output = teeOwnerChildOutput(terminal.Output, tail)
	ownerChildTerminal(t, "native archive terminal", executable, terminal, tail, started)
	capture := ownerterminal.CaptureOutput(terminal.Output)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		_ = terminal.Close(cleanup)
		if capture.Join(cleanup) != nil {
			t.Error("native archive terminal output did not join")
		}
		for _, private := range []string{nativeArchivePassword, nativeArchiveMaster, nativeArchiveValue, nativeArchiveExcluded, nativeArchiveCredential, nativeArchiveMCPBasic, nativeArchiveMCPBearer, nativeArchiveMCPHeader, nativeArchiveMCPBearerHeader, nativeArchiveMCPExcluded, nativeArchiveMCPExcludedHeader} {
			if capture.Contains([]byte(private)) {
				t.Error("native archive terminal disclosed private data")
			}
		}
		capture.Clear()
	}()
	ending := byte('\n')
	if runtime.GOOS == "windows" {
		ending = '\r'
	}
	unlock := append([]byte(nativeArchivePassword), ending)
	defer clear(unlock)
	steps = append([]nativeArchiveInput{{"Vault secret:", unlock}}, steps...)
	for _, step := range steps {
		captureWaitDiag(t, lifetime, capture, step.marker, "native archive command missed terminal barrier \""+step.marker+"\"")
		if len(step.value) != 0 {
			_, err := terminal.Input.Write(step.value)
			nativeArchiveMust(t, err)
		}
	}
	if err := terminal.Wait(lifetime); err != nil {
		// Tell a timeout from a child that exited with an error; both used to read the same.
		class := "child ended with error: " + flakediag.Tail(err.Error(), 200)
		if lifetime.Err() != nil {
			class = "lifetime expired: " + lifetime.Err().Error()
		}
		t.Fatal("native archive command did not complete its explicit decision (" + class + ")")
	}
	if !cancelled {
		captureWaitDiag(t, lifetime, capture, "Owner command completed; encrypted persistence confirmed.", "native archive command omitted its persistence receipt")
	}
}

func nativeArchiveApply(value string) []byte {
	return append([]byte(value), '\t', '\r')
}

func TestVaultOwnerArchiveFullProfile(t *testing.T) {
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
	nativeArchiveCommand(t, ctx, database, true, secretArgs, nativeArchiveInput{"Value:", []byte("\x1b")})
	if !bytes.Equal(before, importBytes(t, database)) {
		t.Fatal("cancelled native value form changed ciphertext")
	}
	nativeArchiveCommand(t, ctx, database, false, secretArgs, nativeArchiveInput{"Value:", nativeArchiveApply(nativeArchiveValue)})
	nativeArchiveCommand(t, ctx, database, false, []string{"add-secret", "--scope", "global", "--name", "excluded-value"}, nativeArchiveInput{"Value:", nativeArchiveApply(nativeArchiveExcluded)})
	status := control.Backend().Status()
	if status.Database.Err != nil || status.Database.Revision != status.Database.SavedRevision {
		t.Fatal("native value helper did not update the parent saved state")
	}
	loaded, err := vault.Load(database, []byte(nativeArchivePassword))
	nativeArchiveMust(t, err)
	alias, reference := "", ""
	for key, binding := range loaded.Secrets {
		if binding.ServerID == server {
			alias, reference = key, binding.Ref
		}
	}
	loaded.Close()
	if alias == "" {
		t.Fatal("native value helper did not persist its server scope")
	}
	beforeExport := importBytes(t, database)
	archives := make(map[string]string)
	for _, format := range []string{"encrypted", "plaintext"} {
		archive := filepath.Join(t.TempDir(), "selected.zip")
		arguments := []string{"export", "--scope", "account", "--server", "archive-source", "--account", "selected", "--mcp-accounts", strings.Join([]string{mcpAccounts["public"], mcpAccounts["basic"], mcpAccounts["bearer"]}, ","), "--destination", archive, "--format", format}
		confirmation := ""
		if format == "plaintext" {
			confirmation = "EXPORT PLAINTEXT"
			nativeArchiveCommand(t, ctx, database, true, arguments, nativeArchiveInput{"Confirmation:", []byte("\x1b")})
			if _, err := os.Lstat(archive); !os.IsNotExist(err) {
				t.Fatal("cancelled native plaintext disclosure created an artifact")
			}
		}
		nativeArchiveCommand(t, ctx, database, false, arguments, nativeArchiveInput{"Confirmation:", nativeArchiveApply(confirmation)})
		verifyNativeArchive(t, ctx, archive, format == "encrypted", server, alias, mcpServerID, mcpAccounts)
		archives[format] = archive
	}
	if !bytes.Equal(beforeExport, importBytes(t, database)) {
		t.Fatal("native selected export changed its source ciphertext")
	}
	archiveDigest := importDigest(t, archives["encrypted"])
	if _, err := control.Backend().Metadata(); err != nil {
		t.Fatal("native export helper detach closed its coordinator")
	}
	nativeArchiveMust(t, control.Close(ctx))
	destination, target, _ := nativeArchiveDatabase(t, ctx, store, id, false)
	nativeArchiveCommand(t, ctx, target, false, []string{"import", "--file", archives["encrypted"]},
		nativeArchiveInput{"Archive password:", nativeArchiveApply(nativeArchivePassword)},
		nativeArchiveInput{"MCP server \"archive-mcp\"", nil},
		nativeArchiveInput{"MCP account \"basic\"", nil},
		nativeArchiveInput{"[Confirm import", []byte("\r")},
		nativeArchiveInput{"Type IMPORT", nativeArchiveApply("IMPORT")})
	imported, err := vault.Load(target, []byte(nativeArchivePassword))
	nativeArchiveMust(t, err)
	defer imported.Close()
	if len(imported.Targets) != 1 || len(imported.Secrets) != 1 || imported.Secrets[alias].ServerID != server || imported.Secrets[alias].Ref == reference || imported.OwnerStore == nil || imported.OwnerStore.StoreID != id {
		t.Fatal("native import lost selection, link scope or fresh publication")
	}
	verifyNativeMCP(t, imported, mcpServerID, mcpAccounts, true, true)
	profile, err := imported.AccountProfile(server, "selected")
	nativeArchiveMust(t, err)
	if !bytes.Equal(imported.Targets[profile].Password, []byte(nativeArchiveCredential)) {
		t.Fatal("native import lost the selected private credential")
	}
	readback := filepath.Join(t.TempDir(), "readback.zip")
	freshMCPServerID, freshMCPAccounts := nativeArchiveMCPSelection(t, destination)
	nativeArchiveCommand(t, ctx, target, false, []string{"export", "--scope", "account", "--server", "archive-source", "--account", "selected", "--destination", readback, "--format", "plaintext"}, nativeArchiveInput{"Confirmation:", []byte("EXPORT PLAINTEXT\t\t\r")})
	verifyNativeArchive(t, ctx, readback, false, server, alias, "", nil)
	beforeMCPOnly := importBytes(t, target)
	mcpOnly := filepath.Join(t.TempDir(), "mcp-only.zip")
	nativeArchiveCommand(t, ctx, target, false, []string{"export", "--scope", "mcp", "--mcp-accounts", strings.Join([]string{freshMCPAccounts["public"], freshMCPAccounts["basic"], freshMCPAccounts["bearer"]}, ","), "--destination", mcpOnly, "--format", "plaintext"}, nativeArchiveInput{"Confirmation:", nativeArchiveApply("EXPORT PLAINTEXT")})
	verifyNativeMCPOnlyArchive(t, ctx, mcpOnly, freshMCPServerID, freshMCPAccounts)
	if !bytes.Equal(beforeMCPOnly, importBytes(t, target)) {
		t.Fatal("native MCP-only export changed its source ciphertext")
	}
	if archiveDigest != importDigest(t, archives["encrypted"]) {
		t.Fatal("native import changed its source archive")
	}
	nativeArchiveMust(t, destination.Close(ctx))
	role, err := ownerlocal.Listen(target)
	nativeArchiveMust(t, err)
	nativeArchiveMust(t, role.Close())
}

func verifyNativeArchive(t *testing.T, ctx context.Context, path string, encrypted bool, server, alias, mcpServerID string, mcpAccounts map[string]string) {
	t.Helper()
	var password []byte
	if encrypted {
		password = []byte(nativeArchivePassword)
		defer clear(password)
	}
	archive, err := ownerarchive.ReadFile(ctx, path, password)
	nativeArchiveMust(t, err)
	defer archive.Close()
	if archive.Encrypted() != encrypted || len(archive.SecretIDs()) != 1 || archive.SecretIDs()[0] != alias {
		t.Fatal("native archive included unselected values or changed encryption mode")
	}
	value, ok := archive.Value(alias)
	if !ok || !bytes.Equal(value, []byte(nativeArchiveValue)) {
		t.Fatal("native archive lost the exact private value")
	}
	defer clear(value)
	data := archive.Database()
	defer clear(data)
	var selected vault.Vault
	nativeArchiveMust(t, pure.LoadsInto(string(data), &selected))
	defer selected.Close()
	if selected.OwnerStore != nil || len(selected.Servers) != 1 || len(selected.Targets) != 1 || len(selected.Secrets) != 1 || len(selected.Servers[server].Accounts) != 1 || selected.Secrets[alias].ServerID != server {
		t.Fatal("native archive included unselected credentials, scopes or master link")
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
	if servers["archive-mcp"] == "" || len(accounts) < 3 {
		t.Fatal("native MCP archive fixture metadata is incomplete")
	}
	return servers["archive-mcp"], accounts
}

func verifyNativeMCPOnlyArchive(t *testing.T, ctx context.Context, path, sourceServerID string, sourceIDs map[string]string) {
	t.Helper()
	archive, err := ownerarchive.ReadFile(ctx, path, nil)
	nativeArchiveMust(t, err)
	defer archive.Close()
	if archive.Encrypted() || len(archive.SecretIDs()) != 0 {
		t.Fatal("native MCP-only archive added SSH/application values or changed format")
	}
	data := archive.Database()
	defer clear(data)
	var selected vault.Vault
	nativeArchiveMust(t, pure.LoadsInto(string(data), &selected))
	defer selected.Close()
	if selected.OwnerStore != nil || len(selected.Servers) != 0 || len(selected.Targets) != 0 || len(selected.Secrets) != 0 {
		t.Fatal("native MCP-only archive attached SSH identities or values")
	}
	verifyNativeMCP(t, &selected, sourceServerID, sourceIDs, false, false)
}

func verifyNativeMCP(t *testing.T, selected *vault.Vault, sourceServerID string, sourceIDs map[string]string, freshIDs, expectLast bool) {
	t.Helper()
	if selected.RemoteMCP == nil || len(selected.RemoteMCP.Servers) != 1 || len(selected.RemoteMCP.Accounts) != 3 {
		t.Fatal("native archive did not preserve exactly the selected MCP accounts")
	}
	var serverID string
	for id, server := range selected.RemoteMCP.Servers {
		serverID = id
		if server.Name != "archive-mcp" || server.URL != "https://archive.invalid/mcp" || server.Revision != 1 || (id == sourceServerID) != !freshIDs {
			t.Fatal("native MCP server identity or metadata changed")
		}
	}
	if serverID == "" {
		t.Fatal("native MCP server is missing")
	}
	seen := make(map[string]bool)
	for id, account := range selected.RemoteMCP.Accounts {
		if account.ServerID != serverID || account.Revision != 1 || (id == sourceIDs[account.Name]) != !freshIDs {
			t.Fatal("native MCP account identity or revision changed")
		}
		seen[account.Name] = true
		switch account.Name {
		case "public":
			if account.Auth.Kind != "none" || len(account.Auth.Secret) != 0 || len(account.Headers) != 0 {
				t.Fatal("native public MCP account changed")
			}
		case "basic":
			if account.Auth.Kind != "basic" || account.Auth.Username != "synthetic-mcp-user" || !bytes.Equal(account.Auth.Secret, []byte(nativeArchiveMCPBasic)) || len(account.Headers) != 1 || account.Headers[0].Name != "X-Archive-Key" || !bytes.Equal(account.Headers[0].Value, []byte(nativeArchiveMCPHeader)) {
				t.Fatal("native basic MCP credentials or header changed")
			}
		case "not-selected":
			t.Fatal("native archive included an unselected MCP account")
		case "bearer":
			if account.Auth.Kind != "bearer" || !bytes.Equal(account.Auth.Secret, []byte(nativeArchiveMCPBearer)) || len(account.Headers) != 1 || account.Headers[0].Name != "X-Bearer-Key" || !bytes.Equal(account.Headers[0].Value, []byte(nativeArchiveMCPBearerHeader)) {
				t.Fatal("native bearer MCP credentials or header changed")
			}
		default:
			t.Fatal("native archive included an unselected MCP account")
		}
	}
	if !seen["public"] || !seen["basic"] || !seen["bearer"] {
		t.Fatal("native MCP authentication kind was omitted")
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
				if !ok || account.ServerID != binding.ServerID || selected.RemoteMCP.Servers[binding.ServerID].Revision != binding.ServerRevision || account.Revision != binding.AccountRevision {
					t.Fatal("native MCP Last contains an unbound identity")
				}
			}
		}
	} else if len(selected.RemoteMCP.Last) != 0 {
		t.Fatal("native MCP-only selection invented an SSH Last context")
	}
}
