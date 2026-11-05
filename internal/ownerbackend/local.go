package ownerbackend

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type manager interface {
	Metadata() (vault.DirectoryMetadata, error)
	Status() ownerdb.Status
	Snapshot() (ownerdb.Snapshot, error)
	ImportStatus() ownerdb.ImportStatus
	Edit(func(*vault.Vault) error) error
	EditAt(uint64, func(*vault.Vault) error) error
	Submit(vault.OwnerChange) error
	SubmitAt(uint64, vault.OwnerChange) error
	Export(ownerdb.ExportRequest) error
	ExportAt(uint64, ownerdb.ExportRequest) error
	Link(string, []byte) error
	LinkAt(uint64, string, []byte) error
	InspectImport(string, []byte) error
	InspectImportAt(uint64, string, []byte) error
	ConfirmImport() error
	ConfirmImportAt(uint64) error
	ResumeImport() error
	ResumeImportAt(uint64) error
	AbortImport() error
	AbortImportAt(uint64) error
	RetryDatabase() error
	RetryDatabaseAt(uint64) error
	Reconcile() error
	ReconcileAt(uint64) error
	ResumeDraft() error
	ResumeDraftAt(uint64) error
	CancelDraft() error
	CancelDraftAt(uint64) error
	Flush(context.Context) error
	Close(context.Context) error
}

type Local struct {
	manager  manager
	expected *uint64
}

func New(m *ownerdb.Manager) *Local { return &Local{manager: m} }
func (b *Local) AtRevision(revision uint64) ownertui.Backend {
	return &Local{manager: b.manager, expected: &revision}
}
func (b *Local) OwnerSnapshot() (vault.DirectoryMetadata, ownerdb.Status, ownerdb.ImportStatus, error) {
	snapshot, err := b.manager.Snapshot()
	return snapshot.Directory, snapshot.Status, snapshot.Import, err
}
func (b *Local) Metadata() (vault.DirectoryMetadata, error) { return b.manager.Metadata() }
func (b *Local) Status() ownerdb.Status                     { return b.manager.Status() }
func (b *Local) ImportStatus() ownerdb.ImportStatus         { return b.manager.ImportStatus() }
func (b *Local) Flush(ctx context.Context) error            { return b.manager.Flush(ctx) }
func (b *Local) Close(ctx context.Context) error            { return b.manager.Close(ctx) }

func (b *Local) decision(at func(uint64) error, current func() error) error {
	if b.expected != nil {
		return at(*b.expected)
	}
	return current()
}
func (b *Local) ConfirmImport() error {
	return b.decision(b.manager.ConfirmImportAt, b.manager.ConfirmImport)
}
func (b *Local) ResumeImport() error {
	return b.decision(b.manager.ResumeImportAt, b.manager.ResumeImport)
}
func (b *Local) AbortImport() error {
	return b.decision(b.manager.AbortImportAt, b.manager.AbortImport)
}
func (b *Local) RetryDatabase() error {
	return b.decision(b.manager.RetryDatabaseAt, b.manager.RetryDatabase)
}
func (b *Local) Reconcile() error { return b.decision(b.manager.ReconcileAt, b.manager.Reconcile) }
func (b *Local) ResumeDraft() error {
	return b.decision(b.manager.ResumeDraftAt, b.manager.ResumeDraft)
}
func (b *Local) CancelDraft() error {
	return b.decision(b.manager.CancelDraftAt, b.manager.CancelDraft)
}

func (b *Local) Edit(edit func(*vault.Vault) error) error {
	if b.expected != nil {
		return b.manager.EditAt(*b.expected, edit)
	}
	return b.manager.Edit(edit)
}
func (b *Local) Submit(change vault.OwnerChange) error {
	if b.expected != nil {
		return b.manager.SubmitAt(*b.expected, change)
	}
	return b.manager.Submit(change)
}
func (b *Local) Link(directory string, master []byte) error {
	if b.expected != nil {
		return b.manager.LinkAt(*b.expected, directory, master)
	}
	return b.manager.Link(directory, master)
}
func (b *Local) Export(request ownerdb.ExportRequest) error {
	if b.expected != nil {
		return b.manager.ExportAt(*b.expected, request)
	}
	return b.manager.Export(request)
}
func (b *Local) InspectImport(path string, password []byte) error {
	if b.expected != nil {
		return b.manager.InspectImportAt(*b.expected, path, password)
	}
	return b.manager.InspectImport(path, password)
}
