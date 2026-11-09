package ownerbackend

import (
	"context"
	"path/filepath"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrpc"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type remoteClient interface {
	Execute(context.Context, ownerpacket.Command) (ownerdb.Snapshot, error)
	Close()
}

// Remote borrows an authenticated client; helpers must also defer client.Close.
// Form closure detaches the peer after flush, never the keeper or parent unlock.
type Remote struct {
	ctx      context.Context
	client   remoteClient
	expected *uint64
	plan     *uint64
}

func NewRemote(ctx context.Context, client *ownerrpc.Client) (*Remote, error) {
	if ctx == nil || ctx.Err() != nil || client == nil {
		return nil, ownerpacket.ErrProtocol
	}
	return &Remote{ctx: ctx, client: client}, nil
}

func (b *Remote) AtRevision(revision uint64) ownertui.Backend {
	return &Remote{ctx: b.ctx, client: b.client, expected: &revision}
}

func (b *Remote) AtImportPlan(revision, plan uint64) ownertui.Backend {
	return &Remote{ctx: b.ctx, client: b.client, expected: &revision, plan: &plan}
}

func (b *Remote) execute(command ownerpacket.Command) (ownerdb.Snapshot, error) {
	ctx, cancel := context.WithTimeout(b.ctx, time.Minute)
	defer cancel()
	return b.client.Execute(ctx, command)
}

func (b *Remote) OwnerSnapshot() (vault.DirectoryMetadata, ownerdb.Status, ownerdb.ImportStatus, error) {
	snapshot, err := b.execute(ownerpacket.Command{Operation: "snapshot"})
	return snapshot.Directory, snapshot.Status, snapshot.Import, err
}

func (b *Remote) Metadata() (vault.DirectoryMetadata, error) {
	directory, _, _, err := b.OwnerSnapshot()
	return directory, err
}
func (b *Remote) Status() ownerdb.Status {
	_, status, _, err := b.OwnerSnapshot()
	if err != nil {
		status.Err = err
	}
	return status
}
func (b *Remote) ImportStatus() ownerdb.ImportStatus {
	_, _, imports, err := b.OwnerSnapshot()
	if err != nil {
		imports.Err = err
	}
	return imports
}

func (b *Remote) mutate(command ownerpacket.Command) error {
	if b.expected == nil {
		return vault.ErrOwnerRevision
	}
	if command.Operation == "confirm-import" || (command.Operation == "recovery" && (command.Recovery == "resume-import" || command.Recovery == "abort-import")) {
		if b.plan == nil || *b.plan == 0 {
			return ownerdb.ErrPending
		}
		command.Plan = *b.plan
	}
	revision := *b.expected
	command.Revision = &revision
	if err := helperPaths(&command); err != nil {
		return err
	}
	_, err := b.execute(command)
	return err
}

// Resolve owner-selected paths in the helper, never in the keeper's cwd.
func helperPaths(command *ownerpacket.Command) error {
	var path *string
	switch {
	case command.Link != nil:
		path = &command.Link.Directory
	case command.Export != nil:
		path = &command.Export.Destination
	case command.Inspect != nil:
		path = &command.Inspect.Path
	case command.Directory != nil:
		change := *command.Directory
		if !change.Valid() {
			return ownerpacket.ErrProtocol
		}
		index := -1
		switch change.Action {
		case "add-server":
			if string(change.Fields[4]) == "key" {
				index = 5
			}
		case "add-account", "edit-account":
			if string(change.Fields[2]) == "key" {
				index = 3
			}
		}
		if index >= 0 && len(change.Fields[index]) != 0 {
			absolute, err := filepath.Abs(string(change.Fields[index]))
			if err != nil {
				return ownerpacket.ErrProtocol
			}
			change.Fields = append([][]byte(nil), change.Fields...)
			change.Fields[index] = []byte(absolute)
			command.Directory = &change
		}
	}
	if path != nil {
		if *path == "" {
			return ownerpacket.ErrProtocol
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return ownerpacket.ErrProtocol
		}
		*path = absolute
	}
	return nil
}

// Arbitrary callbacks cannot cross the closed owner channel.
func (b *Remote) Edit(func(*vault.Vault) error) error { return ownerpacket.ErrProtocol }
func (b *Remote) ApplyDirectory(change ownerpacket.DirectoryChange) error {
	return b.mutate(ownerpacket.Command{Operation: "directory", Directory: &change})
}
func (b *Remote) Submit(change vault.OwnerChange) error {
	return b.mutate(ownerpacket.Command{Operation: "secret", Secret: &ownerpacket.SecretChange{
		Action: change.Action, AliasID: change.AliasID, Name: change.Name, ServerID: change.ServerID,
		ObjectID: change.ObjectID, PreviousReference: change.PreviousReference, MediaType: change.MediaType, Value: change.Value,
	}})
}
func (b *Remote) Link(directory string, master []byte) error {
	return b.mutate(ownerpacket.Command{Operation: "link", Link: &ownerpacket.Link{Directory: directory, Master: master}})
}
func (b *Remote) Export(request ownerdb.ExportRequest) error {
	return b.mutate(ownerpacket.Command{Operation: "export", Export: &ownerpacket.Export{
		Servers: request.Selection.Servers, RemoteMCP: append([]mcpdirectory.Binding(nil), request.Selection.RemoteMCP...), Global: request.Selection.GlobalSecrets,
		Destination: request.Destination, Confirmation: request.PlaintextConfirmation,
	}})
}
func (b *Remote) InspectImport(path string, password []byte) error {
	return b.mutate(ownerpacket.Command{Operation: "inspect-import", Inspect: &ownerpacket.Inspect{Path: path, Password: password}})
}
func (b *Remote) ConfirmImport() error {
	return b.mutate(ownerpacket.Command{Operation: "confirm-import"})
}
func (b *Remote) recover(action string) error {
	return b.mutate(ownerpacket.Command{Operation: "recovery", Recovery: action})
}
func (b *Remote) ResumeImport() error  { return b.recover("resume-import") }
func (b *Remote) AbortImport() error   { return b.recover("abort-import") }
func (b *Remote) RetryDatabase() error { return b.recover("retry-db") }
func (b *Remote) Reconcile() error     { return b.recover("reconcile") }
func (b *Remote) ResumeDraft() error   { return b.recover("resume-draft") }
func (b *Remote) CancelDraft() error   { return b.recover("cancel-draft") }

func (b *Remote) Flush(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(b.ctx, time.Minute)
	defer cancel()
	if ctx == nil {
		return ownerpacket.ErrProtocol
	}
	// Respect the initiating caller as well as the helper lifetime.
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		var release context.CancelFunc
		bounded, release = context.WithDeadline(bounded, deadline)
		defer release()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, err := b.client.Execute(bounded, ownerpacket.Command{Operation: "flush"})
	return err
}
func (b *Remote) Close(ctx context.Context) error {
	if err := b.Flush(ctx); err != nil {
		return err
	}
	b.client.Close()
	return nil
}
