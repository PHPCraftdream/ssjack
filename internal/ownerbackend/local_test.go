package ownerbackend

import (
	"context"
	"errors"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var refusal = errors.New("synthetic owner refusal")

type recorder struct {
	*ownerdb.Manager
	action    string
	revision  uint64
	snapshots uint64
}

func (r *recorder) record(action string, revision uint64) error {
	r.action, r.revision = action, revision
	return refusal
}
func (r *recorder) EditAt(revision uint64, _ func(*vault.Vault) error) error {
	return r.record("edit", revision)
}
func (r *recorder) SubmitAt(revision uint64, _ vault.OwnerChange) error {
	return r.record("submit", revision)
}
func (r *recorder) LinkAt(revision uint64, _ string, _ []byte) error {
	return r.record("link", revision)
}
func (r *recorder) ExportAt(revision uint64, _ ownerdb.ExportRequest) error {
	return r.record("export", revision)
}
func (r *recorder) InspectImportAt(revision uint64, _ string, _ []byte) error {
	return r.record("inspect", revision)
}
func (r *recorder) ConfirmImportAt(revision uint64) error { return r.record("confirm", revision) }
func (r *recorder) ResumeImportAt(revision uint64) error  { return r.record("resume-import", revision) }
func (r *recorder) AbortImportAt(revision uint64) error   { return r.record("abort-import", revision) }
func (r *recorder) RetryDatabaseAt(revision uint64) error { return r.record("retry", revision) }
func (r *recorder) ReconcileAt(revision uint64) error     { return r.record("reconcile", revision) }
func (r *recorder) ResumeDraftAt(revision uint64) error   { return r.record("resume-draft", revision) }
func (r *recorder) CancelDraftAt(revision uint64) error   { return r.record("cancel-draft", revision) }
func (r *recorder) Edit(_ func(*vault.Vault) error) error { return r.record("unscoped-edit", 0) }
func (r *recorder) Snapshot() (ownerdb.Snapshot, error) {
	r.snapshots++
	return ownerdb.Snapshot{
		Directory: vault.DirectoryMetadata{Servers: []vault.ServerMetadata{{ID: "server", Name: "production", Address: "synthetic.invalid:22"}}},
		Status:    ownerdb.Status{Database: vault.SessionStatus{Revision: r.snapshots}}}, nil
}

func TestEveryScopedMutationUsesThePinnedAdmissionAPI(t *testing.T) {
	cases := map[string]func(ownertui.Backend) error{
		"edit":          func(b ownertui.Backend) error { return b.Edit(func(*vault.Vault) error { return nil }) },
		"submit":        func(b ownertui.Backend) error { return b.Submit(vault.OwnerChange{}) },
		"link":          func(b ownertui.Backend) error { return b.Link("synthetic", []byte("synthetic-master")) },
		"export":        func(b ownertui.Backend) error { return b.Export(ownerdb.ExportRequest{}) },
		"inspect":       func(b ownertui.Backend) error { return b.InspectImport("synthetic.zip", []byte("synthetic-password")) },
		"confirm":       func(b ownertui.Backend) error { return b.ConfirmImport() },
		"resume-import": func(b ownertui.Backend) error { return b.ResumeImport() },
		"abort-import":  func(b ownertui.Backend) error { return b.AbortImport() },
		"retry":         func(b ownertui.Backend) error { return b.RetryDatabase() },
		"reconcile":     func(b ownertui.Backend) error { return b.Reconcile() },
		"resume-draft":  func(b ownertui.Backend) error { return b.ResumeDraft() },
		"cancel-draft":  func(b ownertui.Backend) error { return b.CancelDraft() },
	}
	for action, call := range cases {
		t.Run(action, func(t *testing.T) {
			r := &recorder{}
			original := &Local{manager: r}
			if err := call(original.AtRevision(42)); !errors.Is(err, refusal) || r.action != action || r.revision != 42 || original.expected != nil {
				t.Fatal("scoped operation lost its revision, error or immutable original backend")
			}
		})
	}
}

func TestUnscopedOwnerBackendRemainsIndependent(t *testing.T) {
	r := &recorder{}
	original := &Local{manager: r}
	original.AtRevision(42)
	if err := original.Edit(func(*vault.Vault) error { return nil }); !errors.Is(err, refusal) || r.action != "unscoped-edit" {
		t.Fatal("creating an operation scope changed the retained backend")
	}
}

func TestCommandAndMenuPinTheAtomicDisplayedSnapshot(t *testing.T) {
	for _, parameterized := range []bool{false, true} {
		r := &recorder{}
		model := ownertui.New(context.Background(), &Local{manager: r})
		if parameterized {
			request, err := ownercommand.Parse([]string{"rename-server", "--server", "production", "--name", "changed"}, "", "")
			if err != nil {
				t.Fatal(err)
			}
			if err := model.ConfigureCommand(request); err != nil {
				t.Fatal(err)
			}
		} else {
			model.Update(model.Init()())
			if err := model.Select("production", ""); err != nil {
				t.Fatal(err)
			}
			model.Update(tea.KeyPressMsg{Code: 13})
			model.Update(tea.PasteMsg{Content: "changed"})
			model.Update(tea.KeyPressMsg{Code: 9})
		}
		displayed := r.snapshots
		_, operation := model.Update(tea.KeyPressMsg{Code: 13})
		if operation == nil {
			t.Fatal("shared owner form did not reach Apply")
		}
		model.Update(operation())
		if r.action != "edit" || r.revision != displayed {
			t.Fatal("owner form combined metadata with another snapshot's revision")
		}
		model.ClearInput()
	}
}
