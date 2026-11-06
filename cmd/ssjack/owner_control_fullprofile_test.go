package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultOwnerControlFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production owner helper control is CI-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	public, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	server := startLoopbackSSH(t, public, connectPassword, "owner-control")
	v := vault.NewDirectory()
	defer v.Close()
	target := vault.Target{Address: server.address(), User: "second", Password: []byte(connectPassword), HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.hostKey))}, Usage: "both"}
	defer clear(target.Password)
	serverID, err := v.AddServer("production", "main", target)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("synthetic owner control password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "control.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	local, err := ownercontrol.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := local.Close(ctx); err != nil {
			t.Error("standalone control did not close")
		}
	}()
	helper, err := ownercontrol.Open(ctx, path, password)
	if err != nil {
		t.Fatal("helper did not attach to the existing coordinator")
	}
	defer helper.Detach()
	metadata, err := helper.Backend().Metadata()
	if err != nil || len(metadata.Servers) != 1 {
		t.Fatal("remote helper lost directory metadata")
	}
	status := helper.Backend().Status()
	selected := ownertui.Connection{ServerID: serverID, Account: "main", Revision: status.Database.Revision}
	config, address, err := helper.HumanSSH(ctx, selected)
	if err != nil {
		t.Fatal("helper could not capture a human-permitted saved login")
	}
	change := ownerpacket.DirectoryChange{Action: "edit-server", ServerID: serverID, Fields: [][]byte{[]byte("127.0.0.1:1"), nil}}
	scoped := helper.Backend().(interface {
		AtImportPlan(uint64, uint64) ownertui.Backend
	}).AtImportPlan(selected.Revision, 0)
	if err := scoped.(interface {
		ApplyDirectory(ownerpacket.DirectoryChange) error
	}).ApplyDirectory(change); err != nil {
		t.Fatal(err)
	}
	if err := helper.Backend().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := helper.HumanSSH(ctx, selected); !errors.Is(err, vault.ErrOwnerRevision) {
		t.Fatal("stale human selection adopted newer account state")
	}
	runner, err := remote.NewCredentialRunner("captured", address, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner(ctx, "captured", "true", io.Discard, io.Discard); err == nil {
		t.Fatal("shell-only SSH fixture accepted exec")
	}
	if got := server.authentications(); len(got) != 1 || got[0] != "second|password" {
		t.Fatal("captured helper config changed after saved edits or byte cleanup")
	}
	if err := helper.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := local.Backend().Metadata(); err != nil {
		t.Fatal("remote helper detach closed the local coordinator")
	}
	t.Run("native-command-helper", func(t *testing.T) {
		nativeOwnerCommandAcceptance(t, ctx, path, password, serverID, "native-added", local)
	})
	if err := local.Close(ctx); err != nil {
		t.Fatal(err)
	}
	reopened, err := ownercontrol.Open(ctx, path, password)
	if err != nil {
		t.Fatal("closed standalone control retained the writer role")
	}
	if err := reopened.Close(ctx); err != nil {
		t.Fatal(err)
	}
	t.Run("actual-keeper-process", func(t *testing.T) {
		nativeKeeperProcessAcceptance(t, ctx, path, password, serverID, "production")
	})
}
