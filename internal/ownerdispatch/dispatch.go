// Package ownerdispatch routes authenticated human-owner decisions, never MCP tools.
package ownerdispatch

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/owneredit"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

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
	manager manager
	gate    chan struct{}
	owner   *Peer
	plan    uint64
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

func (d *Dispatcher) route(ctx context.Context, c *ownerpacket.Command) error {
	if c.Operation == "flush" {
		return d.manager.Flush(ctx)
	}
	revision := *c.Revision
	switch c.Operation {
	case "directory":
		return d.manager.EditAt(revision, func(v *vault.Vault) error { return owneredit.Apply(v, *c.Directory) })
	case "secret":
		return d.manager.SubmitAt(revision, vault.OwnerChange(*c.Secret))
	case "link":
		return d.manager.LinkAt(revision, c.Link.Directory, c.Link.Master)
	case "export":
		return d.manager.ExportAt(revision, ownerdb.ExportRequest{
			Selection:   vault.ExportSelection{Servers: c.Export.Servers, GlobalSecrets: c.Export.Global},
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
