// Package ownerdispatch routes authenticated human-owner decisions, never MCP tools.
package ownerdispatch

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/owneredit"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type rotationManager interface {
	PrepareRotation(context.Context, uint64, string, string) (ownerrotation.Plan, error)
	DecideRotation(context.Context, uint64, uint64, string, string) (ownerrotation.Plan, error)
}

type manager interface {
	Snapshot() (ownerdb.Snapshot, error)
	EditAt(uint64, func(*vault.Vault) error) error
	SubmitAt(uint64, vault.OwnerChange) error
	LinkAt(uint64, string, []byte) error
	ExportAt(uint64, ownerdb.ExportRequest) error
	InspectImportAt(uint64, string, []byte) error
	ConfirmImportPlanAt(uint64, uint64) error
	ResumeImportPlanAt(uint64, uint64) error
	AbortImportPlanAt(uint64, uint64) error
	ReleaseImportPlan(uint64) error
	RetryDatabaseAt(uint64) error
	ReconcileAt(uint64) error
	ResumeDraftAt(uint64) error
	CancelDraftAt(uint64) error
	Flush(context.Context) error
}

type Dispatcher struct {
	manager        manager
	gate           chan struct{}
	owner          *Peer
	plan           uint64
	rotationOwner  *Peer
	rotationID     string
	rotationPlan   uint64
	orphanPrepared bool
}

func New(m *ownerdb.Manager) (*Dispatcher, error) {
	if m == nil {
		return nil, ownerpacket.ErrProtocol
	}
	if _, err := m.Snapshot(); err != nil {
		return nil, err
	}
	return &Dispatcher{manager: m, gate: make(chan struct{}, 1)}, nil
}

func rotationSaveAllowed(c *ownerpacket.Command) bool {
	return c.Operation == "flush" || (c.Operation == "recovery" && c.Recovery == "retry-db")
}

func (d *Dispatcher) route(ctx context.Context, c *ownerpacket.Command) error {
	if c.Operation == "flush" {
		return d.manager.Flush(ctx)
	}
	revision := *c.Revision
	switch c.Operation {
	case "rotation":
		return ownerpacket.ErrProtocol
	case "directory":
		return d.manager.EditAt(revision, func(v *vault.Vault) error { return owneredit.Apply(v, *c.Directory) })
	case "secret":
		return d.manager.SubmitAt(revision, vault.OwnerChange(*c.Secret))
	case "link":
		return d.manager.LinkAt(revision, c.Link.Directory, c.Link.Master)
	case "export":
		return d.manager.ExportAt(revision, ownerdb.ExportRequest{
			Selection:   vault.ExportSelection{Servers: c.Export.Servers, GlobalSecrets: c.Export.Global, RemoteMCP: append([]mcpdirectory.Binding(nil), c.Export.RemoteMCP...)},
			Destination: c.Export.Destination, PlaintextConfirmation: c.Export.Confirmation,
		})
	case "inspect-import":
		return d.manager.InspectImportAt(revision, c.Inspect.Path, c.Inspect.Password)
	case "confirm-import":
		return d.manager.ConfirmImportPlanAt(revision, c.Plan)
	case "recovery":
		switch c.Recovery {
		case "resume-import":
			return d.manager.ResumeImportPlanAt(revision, c.Plan)
		case "abort-import":
			return d.manager.AbortImportPlanAt(revision, c.Plan)
		case "retry-db":
			return d.manager.RetryDatabaseAt(revision)
		case "reconcile":
			return d.manager.ReconcileAt(revision)
		case "resume-draft":
			return d.manager.ResumeDraftAt(revision)
		case "cancel-draft":
			return d.manager.CancelDraftAt(revision)
		}
	}
	return ownerpacket.ErrProtocol
}

func activeRotation(info *vault.RotationInfo) bool {
	if info == nil {
		return false
	}
	switch info.Phase {
	case vault.RotationPrepared, vault.RotationAttempting, vault.RotationUnknown, vault.RotationAdded, vault.RotationVerified, vault.RotationCommitted:
		return true
	default:
		return false
	}
}

func (d *Dispatcher) observeRotation(s ownerdb.Snapshot) {
	if !activeRotation(s.Rotation) {
		d.rotationOwner, d.rotationID, d.rotationPlan, d.orphanPrepared = nil, "", 0, false
		return
	}
	info := s.Rotation
	if d.rotationID != info.ID || d.rotationPlan != info.PlanID {
		if d.rotationOwner == nil || d.rotationOwner.closed.Load() {
			d.rotationOwner = nil
		}
		d.rotationID, d.rotationPlan = info.ID, info.PlanID
	}
	if d.rotationOwner != nil && d.rotationOwner.closed.Load() && info.Phase == vault.RotationPrepared {
		d.orphanPrepared = true
	}
}

func (d *Dispatcher) routeRotation(ctx context.Context, p *Peer, revision uint64, request *ownerpacket.Rotation, before ownerdb.Snapshot, orphan bool) error {
	api, ok := d.manager.(rotationManager)
	if !ok {
		return ownerpacket.ErrProtocol
	}
	if request.Action == "prepare" {
		if activeRotation(before.Rotation) || d.rotationOwner != nil {
			return ownerdb.ErrPending
		}
		plan, err := api.PrepareRotation(ctx, revision, request.ServerID, request.Account)
		if err == nil {
			d.rotationOwner, d.rotationID, d.rotationPlan, d.orphanPrepared = p, plan.Info.ID, plan.Info.PlanID, false
		}
		return err
	}
	if before.Rotation == nil || before.Rotation.ID != request.ID || before.Rotation.PlanID != request.PlanID {
		return vault.ErrOwnerRevision
	}
	if request.Action == "archive" {
		if before.Rotation.Phase == vault.RotationArchived {
			return vault.ErrOwnerRevision
		}
		if revision != before.Status.Database.Revision {
			return vault.ErrOwnerRevision
		}
		if before.Rotation.Phase != vault.RotationComplete || before.Status.Database.SavedRevision != revision {
			return ownerdb.ErrPending
		}
		if p.seenRotation != request.ID || p.seenRotationPlan != request.PlanID || p.seenRotationRevision != revision {
			return ownerdb.ErrPending
		}
		_, err := api.DecideRotation(ctx, revision, request.PlanID, request.ID, request.Action)
		return err
	}
	if d.rotationOwner != nil && d.rotationOwner != p {
		if !d.rotationOwner.closed.Load() || request.Action != "recover" || !orphan {
			return ownerdb.ErrPending
		}
	}
	if orphan && request.Action != "recover" && !(request.Action == "cancel" && before.Rotation.Phase == vault.RotationPrepared && p.seenRotation == request.ID && p.seenRotationPlan == request.PlanID) {
		return ownerdb.ErrPending
	}
	if request.Action == "recover" && (!orphan || p.seenRotation != request.ID || p.seenRotationPlan != request.PlanID) {
		return ownerdb.ErrPending
	}
	if orphan && request.Action == "cancel" && (before.Rotation.Phase != vault.RotationPrepared || p.seenRotation != request.ID || p.seenRotationPlan != request.PlanID) {
		return ownerdb.ErrPending
	}
	if request.Action == "install" && (orphan || d.orphanPrepared || d.rotationOwner != p || before.Rotation.Phase != vault.RotationPrepared) {
		return ownerdb.ErrPending
	}
	if request.Action == "verify" && before.Rotation.Phase != vault.RotationAttempting && before.Rotation.Phase != vault.RotationUnknown && before.Rotation.Phase != vault.RotationAdded {
		return ownerdb.ErrPending
	}
	if request.Action == "commit" && before.Rotation.Phase != vault.RotationVerified && before.Rotation.Phase != vault.RotationCommitted {
		return ownerdb.ErrPending
	}
	if request.Action == "cancel" && before.Rotation.Phase != vault.RotationPrepared {
		return ownerdb.ErrPending
	}
	if d.rotationOwner == p && (d.rotationID != request.ID || d.rotationPlan != request.PlanID) {
		return ownerdb.ErrPending
	}
	if d.rotationOwner == nil && !orphan && request.Action != "recover" && !(request.Action == "cancel" && p.seenRotation == request.ID && p.seenRotationPlan == request.PlanID && before.Rotation.Phase == vault.RotationPrepared) {
		return ownerdb.ErrPending
	}
	_, err := api.DecideRotation(ctx, revision, request.PlanID, request.ID, request.Action)
	if err != nil {
		return err
	}
	if request.Action == "recover" {
		d.rotationOwner, d.rotationID, d.rotationPlan, d.orphanPrepared = p, request.ID, request.PlanID, orphan && before.Rotation.Phase == vault.RotationPrepared
	}
	if request.Action == "cancel" {
		d.rotationOwner, d.rotationID, d.rotationPlan, d.orphanPrepared = nil, "", 0, false
	}
	return nil
}
