package nativeownercheck

import (
	"context"
	"errors"
	"testing"

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
