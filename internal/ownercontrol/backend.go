package ownercontrol

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/owneredit"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type backend struct {
	ownertui.Backend
	control *Control
}

func (c *Control) Backend() ownertui.Backend       { return &backend{Backend: c.backend, control: c} }
func (b *backend) Close(ctx context.Context) error { return b.control.Close(ctx) }
func (b *backend) ApplyDirectory(change ownerpacket.DirectoryChange) error {
	return owneredit.Dispatch(b.Backend, change)
}
func (b *backend) OwnerSnapshot() (vault.DirectoryMetadata, ownerdb.Status, ownerdb.ImportStatus, error) {
	return b.Backend.(interface {
		OwnerSnapshot() (vault.DirectoryMetadata, ownerdb.Status, ownerdb.ImportStatus, error)
	}).OwnerSnapshot()
}
func (b *backend) AtRevision(revision uint64) ownertui.Backend {
	return &backend{Backend: b.Backend.(interface{ AtRevision(uint64) ownertui.Backend }).AtRevision(revision), control: b.control}
}
func (b *backend) AtImportPlan(revision, plan uint64) ownertui.Backend {
	return &backend{Backend: b.Backend.(interface {
		AtImportPlan(uint64, uint64) ownertui.Backend
	}).AtImportPlan(revision, plan), control: b.control}
}
