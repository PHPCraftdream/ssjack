package ownerbackend

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type remoteRecorder struct {
	command   ownerpacket.Command
	snapshots uint64
	revision  uint64
	plan      uint64
	closed    int
	failure   error
}

func (r *remoteRecorder) Close() { r.closed++ }
func (r *remoteRecorder) Execute(ctx context.Context, command ownerpacket.Command) (ownerdb.Snapshot, error) {
	if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil {
		return ownerdb.Snapshot{}, errors.New("synthetic missing active bound")
	}
	r.command = command
	if command.Directory != nil {
		owned := *command.Directory
		owned.Fields = make([][]byte, len(command.Directory.Fields))
		for i, field := range command.Directory.Fields {
			owned.Fields[i] = append([]byte(nil), field...)
		}
		r.command.Directory = &owned
	}
	if command.Operation == "snapshot" {
		r.snapshots++
		revision := r.revision
		if revision == 0 {
			revision = r.snapshots
		}
		imports := ownerdb.ImportStatus{PlanID: r.plan}
		if r.plan != 0 {
			imports.Phase = ownerdb.ImportStaged
		}
		return ownerdb.Snapshot{
			Directory: vault.DirectoryMetadata{Servers: []vault.ServerMetadata{{ID: "server", Name: "production", Address: "synthetic.invalid:22"}}},
			Import:    imports,
			Status:    ownerdb.Status{Database: vault.SessionStatus{Revision: revision}}}, r.failure
	}
	return ownerdb.Snapshot{}, r.failure
}

func TestRemoteMutationsUseClosedCommandsAndImmutableRevision(t *testing.T) {
	absolute := func(path string) string {
		result, err := filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	change := vault.OwnerChange{Action: "add", AliasID: "alias", Name: "token", ServerID: "server", ObjectID: "object", PreviousReference: "previous", MediaType: "text/plain", Value: []byte("synthetic private value")}
	directory := ownerpacket.DirectoryChange{Action: "rename-server", ServerID: "server", Fields: [][]byte{[]byte("changed")}}
	export := ownerdb.ExportRequest{Selection: vault.ExportSelection{Servers: map[string][]string{"server": {"main"}}, GlobalSecrets: true, RemoteMCP: []mcpdirectory.Binding{{ServerID: "01010101010101010101010101010101", AccountID: "02020202020202020202020202020202", ServerRevision: 3, AccountRevision: 4}}}, Destination: "synthetic.zip", PlaintextConfirmation: "EXPORT PLAINTEXT"}
	cases := []struct {
		call func(*Remote) error
		want ownerpacket.Command
	}{
		{func(b *Remote) error { return b.ApplyDirectory(directory) }, ownerpacket.Command{Operation: "directory", Directory: &directory}},
		{func(b *Remote) error { return b.Submit(change) }, ownerpacket.Command{Operation: "secret", Secret: &ownerpacket.SecretChange{Action: change.Action, AliasID: change.AliasID, Name: change.Name, ServerID: change.ServerID, ObjectID: change.ObjectID, PreviousReference: change.PreviousReference, MediaType: change.MediaType, Value: change.Value}}},
		{func(b *Remote) error { return b.Link("synthetic-store", []byte("synthetic-master")) }, ownerpacket.Command{Operation: "link", Link: &ownerpacket.Link{Directory: absolute("synthetic-store"), Master: []byte("synthetic-master")}}},
		{func(b *Remote) error { return b.Export(export) }, ownerpacket.Command{Operation: "export", Export: &ownerpacket.Export{Servers: export.Selection.Servers, RemoteMCP: append([]mcpdirectory.Binding(nil), export.Selection.RemoteMCP...), Global: true, Destination: absolute(export.Destination), Confirmation: export.PlaintextConfirmation}}},
		{func(b *Remote) error { return b.InspectImport("synthetic.zip", []byte("synthetic-password")) }, ownerpacket.Command{Operation: "inspect-import", Inspect: &ownerpacket.Inspect{Path: absolute("synthetic.zip"), Password: []byte("synthetic-password")}}},
		{func(b *Remote) error { return b.ConfirmImport() }, ownerpacket.Command{Operation: "confirm-import"}},
		{func(b *Remote) error { return b.ResumeImport() }, ownerpacket.Command{Operation: "recovery", Recovery: "resume-import"}},
		{func(b *Remote) error { return b.AbortImport() }, ownerpacket.Command{Operation: "recovery", Recovery: "abort-import"}},
		{func(b *Remote) error { return b.RetryDatabase() }, ownerpacket.Command{Operation: "recovery", Recovery: "retry-db"}},
		{func(b *Remote) error { return b.Reconcile() }, ownerpacket.Command{Operation: "recovery", Recovery: "reconcile"}},
		{func(b *Remote) error { return b.ResumeDraft() }, ownerpacket.Command{Operation: "recovery", Recovery: "resume-draft"}},
		{func(b *Remote) error { return b.CancelDraft() }, ownerpacket.Command{Operation: "recovery", Recovery: "cancel-draft"}},
	}
	for _, test := range cases {
		r := &remoteRecorder{failure: refusal}
		original := &Remote{ctx: context.Background(), client: r}
		if err := test.call(original); !errors.Is(err, vault.ErrOwnerRevision) || r.command.Operation != "" {
			t.Fatal("unscoped remote mutation fetched a revision or reached the wire")
		}
		b := original.AtImportPlan(42, 7).(*Remote)
		if err := test.call(b); !errors.Is(err, refusal) || original.expected != nil {
			t.Fatal("remote form lost its error or changed the retained revision scope")
		}
		revision := uint64(42)
		test.want.Revision = &revision
		if test.want.Operation == "confirm-import" || (test.want.Operation == "recovery" && (test.want.Recovery == "resume-import" || test.want.Recovery == "abort-import")) {
			test.want.Plan = 7
		}
		if !reflect.DeepEqual(r.command, test.want) {
			t.Fatal("remote form changed a closed command's scope or private input")
		}
	}
}

func TestRemoteResolvesOnlyOwnerPathsWithoutChangingCredentialBytes(t *testing.T) {
	for _, kind := range []string{"key", "password"} {
		r := &remoteRecorder{}
		b := (&Remote{ctx: context.Background(), client: r}).AtRevision(7).(*Remote)
		credential := []byte("synthetic-credential")
		change := ownerpacket.DirectoryChange{Action: "add-account", ServerID: "server", Fields: [][]byte{[]byte("main"), []byte("deploy"), []byte(kind), credential, []byte("both")}}
		if err := b.ApplyDirectory(change); err != nil {
			t.Fatal(err)
		}
		want := string(credential)
		if kind == "key" {
			var err error
			want, err = filepath.Abs(want)
			if err != nil {
				t.Fatal(err)
			}
		}
		if string(r.command.Directory.Fields[3]) != want || string(credential) != "synthetic-credential" {
			t.Fatal("remote backend changed a caller buffer or interpreted password bytes as a path")
		}
	}
	r := &remoteRecorder{}
	b := (&Remote{ctx: context.Background(), client: r}).AtRevision(7).(*Remote)
	if err := b.Link("", []byte("synthetic-master")); !errors.Is(err, ownerpacket.ErrProtocol) || r.command.Operation != "" {
		t.Fatal("empty owner path became the helper working directory")
	}
	if err := b.ApplyDirectory(ownerpacket.DirectoryChange{Action: "add-account"}); !errors.Is(err, ownerpacket.ErrProtocol) || r.command.Operation != "" {
		t.Fatal("invalid directory shape reached path interpretation or RPC")
	}
}

func TestRemoteRefusesCallbacksAndDoesNotCloseKeeperOnFailedFlush(t *testing.T) {
	r := &remoteRecorder{failure: refusal}
	b := &Remote{ctx: context.Background(), client: r}
	called := false
	if err := b.Edit(func(*vault.Vault) error { called = true; return nil }); !errors.Is(err, ownerpacket.ErrProtocol) || called || r.command.Operation != "" {
		t.Fatal("remote backend ran or serialized an arbitrary callback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Flush(ctx); !errors.Is(err, context.Canceled) || r.command.Operation != "" {
		t.Fatal("cancelled flush reached the owner channel")
	}
	if err := b.Close(context.Background()); !errors.Is(err, refusal) || r.closed != 0 || r.command.Operation != "flush" {
		t.Fatal("failed flush detached the helper or closed the keeper")
	}
	r.failure = nil
	if err := b.Close(context.Background()); err != nil || r.closed != 1 || r.command.Operation != "flush" {
		t.Fatal("saved helper close did not flush and detach")
	}
}

func TestRemoteFormKeepsItsPlanAcrossSameRevisionRefresh(t *testing.T) {
	r := &remoteRecorder{revision: 42, plan: 17}
	model := ownertui.New(context.Background(), &Remote{ctx: context.Background(), client: r})
	request, err := ownercommand.Parse([]string{"pending", "--action", "abort-import"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := model.ConfigureCommand(request); err != nil {
		t.Fatal(err)
	}
	r.plan = 18
	model.Update(model.Init()())
	r.failure = ownerdb.ErrPending
	_, operation := model.Update(tea.KeyPressMsg{Code: 13})
	if operation == nil {
		t.Fatal("plan-scoped owner form did not reach Apply")
	}
	model.Update(operation())
	if r.command.Operation != "recovery" || r.command.Recovery != "abort-import" || r.command.Plan != 17 || r.command.Revision == nil || *r.command.Revision != 42 || r.plan != 18 {
		t.Fatal("refreshed form substituted a new plan at the same database revision")
	}
	model.ClearInput()
}

func TestRemoteCommandAndMenuUseTypedDisplayedRevision(t *testing.T) {
	for _, parameterized := range []bool{false, true} {
		r := &remoteRecorder{}
		model := ownertui.New(context.Background(), &Remote{ctx: context.Background(), client: r})
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
			t.Fatal("remote shared form did not reach Apply")
		}
		model.Update(operation())
		if r.command.Operation != "directory" || r.command.Revision == nil || *r.command.Revision != displayed || r.command.Directory == nil || r.command.Directory.Action != "rename-server" || string(r.command.Directory.Fields[0]) != "changed" {
			t.Fatal("remote form did not dispatch the typed action at its displayed revision")
		}
		model.ClearInput()
	}
}
