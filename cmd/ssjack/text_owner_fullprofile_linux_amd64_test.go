//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultTextOwnerFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production text-owner startup is CI-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	password := []byte("synthetic unlinked text owner password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "text-owner.ktav")
	v := vault.NewDirectory()
	defer v.Close()
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, credentials, err := startTextOwner(ctx, path, loaded)
	var code int
	var result error
	defer func() {
		finishAgentCredentials(credentials, &code, &result)
		if code != 0 || result != nil {
			t.Error("text owner did not join its service and parent shutdown")
		}
	}()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := owner.Snapshot()
	if err != nil || snapshot.Directory.OwnerStore != nil {
		t.Fatal("unlinked text startup persisted an implicit installation link")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("text owner startup unexpectedly rewrote the encrypted database")
	}
	if competing, err := ownerlocal.Listen(path); !errors.Is(err, ownerlocal.ErrBusy) {
		if competing != nil {
			_ = competing.Close()
		}
		t.Fatal("unlinked text owner failed to retain native writer admission")
	}
	helper, err := ownercontrol.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Detach()
	status := helper.Backend().Status()
	if status.Err != nil || status.Database.Err != nil {
		t.Fatal("text owner helper could not read its revision")
	}
	scoper, ok := helper.Backend().(interface {
		AtRevision(uint64) ownertui.Backend
	})
	if !ok {
		t.Fatal("text owner helper lost scoped admission")
	}
	backend, ok := scoper.AtRevision(status.Database.Revision).(interface {
		ApplyDirectory(ownerpacket.DirectoryChange) error
	})
	if !ok {
		t.Fatal("text owner helper lost typed directory dispatch")
	}
	change := ownerpacket.DirectoryChange{Action: "add-mcp-server", Fields: [][]byte{[]byte("coordinator"), []byte("https://coordinator.invalid/mcp")}}
	if err := backend.ApplyDirectory(change); err != nil {
		t.Fatal(err)
	}
	if err := helper.Backend().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot, err = owner.Snapshot()
	if err != nil || snapshot.Directory.OwnerStore != nil || len(snapshot.Directory.RemoteMCP.Servers) != 1 || snapshot.Status.Database.Revision != status.Database.Revision+1 || snapshot.Status.Database.SavedRevision != snapshot.Status.Database.Revision {
		t.Fatal("unlinked text owner did not coordinate the explicit directory edit")
	}
	if err := helper.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Snapshot(); err != nil {
		t.Fatal("helper detach closed the text owner")
	}
	finishAgentCredentials(credentials, &code, &result)
	if code != 0 || result != nil {
		t.Fatal("text owner shutdown did not join")
	}
	listener, err := ownerlocal.Listen(path)
	if err != nil {
		t.Fatal("text owner shutdown retained its native writer role")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.OwnerStore != nil || reopened.RemoteMCP == nil || len(reopened.RemoteMCP.Servers) != 1 {
		t.Fatal("text owner persistence lost edits or implicitly linked installation material")
	}
}
