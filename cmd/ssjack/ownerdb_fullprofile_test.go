package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func ownerDatabaseAcceptance(t *testing.T, ctx context.Context, storeDirectory, master string, initial appstoreref.Ref) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "synthetic owner fixture")
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	v := vault.New()
	defer v.Close()
	v.Targets["legacy"] = vault.Target{Address: "example.invalid:22", User: "first", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{string(ssh.MarshalAuthorizedKey(public))}}
	if err := v.UpgradeDirectory(); err != nil {
		t.Fatal(err)
	}
	server, err := v.ServerID("legacy")
	if err != nil {
		t.Fatal(err)
	}
	second := v.Targets["legacy"]
	second.PrivateKey, second.Password, second.User = nil, []byte("synthetic SSH account password"), "second"
	defer clear(second.Password)
	if err := v.SetAccount(server, "second", second); err != nil {
		t.Fatal(err)
	}
	encoded, err := appstoreplaceholder.Encode(initial)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := v.BindSecret("", vault.SecretBinding{Name: "initial", Ref: string(encoded)})
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("synthetic owner credential database password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "owner.ssjack.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	manager, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Discard()
	linkMaster := []byte(master)
	linkErr := manager.Link(storeDirectory, linkMaster)
	clear(linkMaster)
	if linkErr != nil {
		t.Fatal(linkErr)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.Submit(vault.OwnerChange{Action: "update", AliasID: alias, Name: "initial", PreviousReference: string(encoded), MediaType: "text/plain", Value: []byte("updated owner fixture value")}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	metadata, err := manager.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	updated, err := appstoreplaceholder.Parse([]byte(metadata.Secrets[alias].Ref))
	if err != nil || updated == initial || updated.ObjectID() != initial.ObjectID() || metadata.OwnerStore.PendingID != "" {
		t.Fatal("owner value update did not finalize an exact new version")
	}
	if err := manager.Submit(vault.OwnerChange{Action: "add", Name: "local", ServerID: server, MediaType: "text/plain", Value: []byte("server-local owner fixture value")}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	metadata, err = manager.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	var localID string
	for id, binding := range metadata.Secrets {
		if binding.Name == "local" && binding.ServerID == server {
			localID = id
		}
	}
	if localID == "" || len(metadata.Secrets) != 2 {
		t.Fatal("owner add lost a scoped or unrelated secret")
	}
	if err := manager.Submit(vault.OwnerChange{Action: "remove", AliasID: localID, Name: "local", ServerID: server, PreviousReference: metadata.Secrets[localID].Ref}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if loaded.OwnerStore.Pending != nil || len(loaded.Secrets) != 1 || loaded.Secrets[alias].Name != "initial" || !bytes.Equal(loaded.Targets["legacy"].PrivateKey, v.Targets["legacy"].PrivateKey) || len(loaded.Servers[server].Accounts) != 2 {
		t.Fatal("owner coordination lost credentials, aliases, or durable completion")
	}
	profile, err := loaded.AccountProfile(server, "second")
	if err != nil || !bytes.Equal(loaded.Targets[profile].Password, second.Password) {
		t.Fatal("owner coordination changed the second SSH account's password")
	}
	if _, err := loaded.StageOwnerChange(vault.OwnerChange{Action: "add", Name: "unsubmitted", MediaType: "text/plain", Value: []byte("retained restart draft")}); err != nil {
		t.Fatal(err)
	}
	if err := vault.SaveUnlocked(ctx, path, loaded); err != nil {
		t.Fatal(err)
	}
	restarted, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Discard()
	if status := restarted.Status(); !status.Pending || status.Busy {
		t.Fatal("startup resumed a pending owner draft without an explicit action")
	}
	if err := restarted.CancelDraft(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Close(ctx); err != nil {
		t.Fatal(err)
	}
	ownerTerminalAcceptance(t, ctx, path, password, v, server)
}
