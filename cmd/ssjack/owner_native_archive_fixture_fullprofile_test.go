package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
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
