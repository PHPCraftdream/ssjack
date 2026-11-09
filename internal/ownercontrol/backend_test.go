package ownercontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type backendProbe struct {
	ownertui.Backend
	revision, plan uint64
	action         string
}

func (p *backendProbe) AtRevision(revision uint64) ownertui.Backend {
	return &backendProbe{revision: revision}
}
func (p *backendProbe) AtImportPlan(revision, plan uint64) ownertui.Backend {
	return &backendProbe{revision: revision, plan: plan}
}
func (p *backendProbe) OwnerSnapshot() (vault.DirectoryMetadata, ownerdb.Status, ownerdb.ImportStatus, error) {
	return vault.DirectoryMetadata{}, ownerdb.Status{Database: vault.SessionStatus{Revision: p.revision}}, ownerdb.ImportStatus{PlanID: p.plan}, nil
}
func (p *backendProbe) ApplyDirectory(change ownerpacket.DirectoryChange) error {
	p.action = change.Action
	return vault.ErrOwnerRevision
}

func TestControlWrapperPreservesAtomicSnapshotAndTypedScopes(t *testing.T) {
	control := &Control{backend: &backendProbe{}}
	original := control.Backend().(*backend)
	scoped := original.AtImportPlan(42, 17).(*backend)
	_, status, imports, err := scoped.OwnerSnapshot()
	if err != nil || status.Database.Revision != 42 || imports.PlanID != 17 || scoped.control != control {
		t.Fatal("control wrapper lost owned operation scope")
	}
	if err := scoped.ApplyDirectory(ownerpacket.DirectoryChange{Action: "rename-server"}); !errors.Is(err, vault.ErrOwnerRevision) || scoped.Backend.(*backendProbe).action != "rename-server" {
		t.Fatal("control wrapper replaced typed directory dispatch with callback")
	}
	_, status, imports, err = original.OwnerSnapshot()
	if err != nil || status.Database.Revision != 0 || imports.PlanID != 0 {
		t.Fatal("scoped control changed retained backend")
	}
}

func TestInvalidControlLifecycleRefusesWithoutAuthority(t *testing.T) {
	if _, err := Open(nil, "", nil); !errors.Is(err, ErrControl) {
		t.Fatal("control accepted absent context")
	}
	control := &Control{closed: true}
	if err := control.Close(nil); !errors.Is(err, ErrControl) {
		t.Fatal("control accepted absent close context")
	}
	if _, _, err := control.HumanSSH(context.Background(), ownertui.Connection{}); !errors.Is(err, ErrControl) {
		t.Fatal("closed control released human SSH authority")
	}
	control.Detach()
}
