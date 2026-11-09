package nativeownercheck

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerservice"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func verifyOwnerControl(t *testing.T, ctx context.Context, path string, password []byte, manager *ownerdb.Manager) {
	t.Helper()
	service, err := ownerservice.Start(ctx, manager)
	must(t, err)
	defer service.Close(ctx)
	control, err := ownercontrol.Open(ctx, path, password)
	must(t, err)
	defer control.Detach()
	backend := control.Backend()
	directory, err := backend.Metadata()
	must(t, err)
	if len(directory.RemoteMCP.Servers) != 1 {
		t.Fatal("attached native control omitted metadata")
	}
	status := backend.Status()
	request := backend.(interface {
		AtImportPlan(uint64, uint64) ownertui.Backend
	}).AtImportPlan(status.Database.Revision, 0)
	change := ownerpacket.DirectoryChange{Action: "add-mcp-server", Fields: [][]byte{[]byte("native-control"), []byte("https://control.invalid/mcp")}}
	must(t, request.(interface {
		ApplyDirectory(ownerpacket.DirectoryChange) error
	}).ApplyDirectory(change))
	must(t, backend.Flush(ctx))
	if err := request.(interface {
		ApplyDirectory(ownerpacket.DirectoryChange) error
	}).ApplyDirectory(change); !errors.Is(err, vault.ErrOwnerRevision) {
		t.Fatal("native control wrapper adopted a newer revision")
	}
	must(t, control.Close(ctx))
	if _, err := manager.Snapshot(); err != nil {
		t.Fatal("helper control closed the live Manager")
	}
	must(t, service.Close(ctx))
}

func guardResult(t *testing.T, snapshot *outputguard.Snapshot, input, expected string) {
	t.Helper()
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &result)
	must(t, err)
	for _, value := range []byte(input) {
		_, err := writer.Write([]byte{value})
		must(t, err)
	}
	must(t, writer.Close())
	if result.String() != expected {
		t.Fatal("private guard capability lost expected literal coverage")
	}
}

func verifyGuardAdmission(t *testing.T, ctx context.Context, path string, manager *ownerdb.Manager) {
	t.Helper()
	var server, account string
	must(t, manager.Edit(func(v *vault.Vault) error {
		v.RemoteMCP = mcpdirectory.New()
		var err error
		server, err = v.RemoteMCP.AddServer("guard-fixture", "https://guard.invalid/mcp")
		if err != nil {
			return err
		}
		account, err = v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: server, Name: "guard", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-old-credential")}})
		return err
	}))
	must(t, manager.Flush(ctx))
	old, err := manager.OutputGuard(ctx)
	must(t, err)
	guardResult(t, old, "synthetic-old-credential|synthetic-new-credential", "[REDACTED]|synthetic-new-credential")
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(t, err)
	must(t, lock.Close())
	defer os.Remove(lockPath)
	must(t, manager.Edit(func(v *vault.Vault) error {
		return v.RemoteMCP.ReplaceAccount(account, mcpdirectory.Account{ServerID: server, Name: "guard", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-new-credential")}})
	}))
	if manager.Flush(ctx) == nil {
		t.Fatal("synthetic lock did not refuse persistence")
	}
	if snapshot, err := manager.OutputGuard(ctx); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("failed save returned an unconfirmed or stale guard")
	}
	must(t, os.Remove(lockPath))
	must(t, manager.RetryDatabase())
	must(t, manager.Flush(ctx))
	current, err := manager.OutputGuard(ctx)
	must(t, err)
	guardResult(t, current, "synthetic-old-credential|synthetic-new-credential", "[REDACTED]|[REDACTED]")
	guardResult(t, old, "synthetic-new-credential", "synthetic-new-credential")
	encoded, err := os.ReadFile(path)
	must(t, err)
	must(t, os.WriteFile(path, append(append([]byte(nil), encoded...), 0), 0600))
	if snapshot, err := manager.OutputGuard(ctx); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("changed ciphertext granted a stale guard")
	}
	must(t, os.WriteFile(path, encoded, 0600))
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if snapshot, err := manager.OutputGuard(cancelled); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("cancelled admission granted a capability")
	}
	current, err = manager.OutputGuard(ctx)
	must(t, err)
	guardResult(t, current, "synthetic-old-credential|synthetic-new-credential", "[REDACTED]|[REDACTED]")
	must(t, manager.Edit(func(v *vault.Vault) error { v.RemoteMCP.Clear(); v.RemoteMCP = nil; return nil }))
	must(t, manager.Flush(ctx))
}

func verifyLinkedGuardAdmission(t *testing.T, ctx context.Context, store string, storeID [16]byte, master []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guard.ktav")
	password := []byte("synthetic linked guard database password")
	defer clear(password)
	v := vault.NewDirectory()
	defer v.Close()
	must(t, v.LinkOwnerStore(vault.OwnerStore{Directory: store, StoreID: hex.EncodeToString(storeID[:]), Master: master}))
	must(t, vault.CreateWithRecords(ctx, path, v, password))
	manager, err := ownerdb.Open(ctx, path, password)
	must(t, err)
	defer manager.Discard()
	must(t, manager.Submit(vault.OwnerChange{Action: "add", Name: "guard-value", MediaType: "text/plain", Value: []byte("synthetic-old-linked-value")}))
	must(t, manager.Flush(ctx))
	old, err := manager.OutputGuard(ctx)
	must(t, err)
	guardResult(t, old, string(master)+"|synthetic-old-linked-value", "[REDACTED]|[REDACTED]")
	metadata, err := manager.Metadata()
	must(t, err)
	var alias string
	for id := range metadata.Secrets {
		alias = id
	}
	must(t, manager.Submit(vault.OwnerChange{Action: "update", AliasID: alias, Name: "guard-value", PreviousReference: metadata.Secrets[alias].Ref, MediaType: "text/plain", Value: []byte("synthetic-new-linked-value")}))
	must(t, manager.Flush(ctx))
	current, err := manager.OutputGuard(ctx)
	must(t, err)
	guardResult(t, current, "synthetic-old-linked-value|synthetic-new-linked-value", "[REDACTED]|[REDACTED]")
	guardResult(t, old, "synthetic-new-linked-value", "synthetic-new-linked-value")
	must(t, manager.Close(ctx))
	if snapshot, err := manager.OutputGuard(ctx); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("closed coordinator granted a capability")
	}
	guardResult(t, current, "synthetic-old-linked-value|synthetic-new-linked-value", "[REDACTED]|[REDACTED]")
}
