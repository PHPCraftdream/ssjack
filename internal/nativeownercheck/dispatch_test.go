package nativeownercheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/PHPCraftdream/ssjack/internal/ownerbackend"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerdispatch"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrpc"
	"github.com/PHPCraftdream/ssjack/internal/ownerservice"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type managerRPCPeer struct {
	client *ownerrpc.Client
	remote *ownerbackend.Remote
	unlock *vault.OwnerUnlock
	server *ownerpacket.Server
	lease  *ownerdispatch.Peer
	conn   ownerlocal.Connection
	cancel context.CancelFunc
	done   chan error
	joined bool
	result error
}

func (p *managerRPCPeer) close() error {
	if p.client != nil {
		p.client.Close()
	} else if p.conn != nil {
		p.conn.Close()
	}
	p.cancel()
	if !p.joined {
		p.result, p.joined = <-p.done, true
	}
	cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p.lease.EndLease(cleanup)
	p.server.Close()
	p.unlock.Close()
	return p.result
}

func verifyOwnerService(t *testing.T, ctx context.Context, path string, manager *ownerdb.Manager) {
	t.Helper()
	before, err := manager.Snapshot()
	must(t, err)
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(t, err)
	must(t, lock.Close())
	defer os.Remove(lockPath)
	must(t, manager.EditAt(before.Status.Database.Revision, func(*vault.Vault) error { return nil }))
	if err := manager.Flush(ctx); err == nil {
		t.Fatal("synthetic commit-lock refusal did not reach save failure")
	}
	service, err := ownerservice.Start(ctx, manager)
	must(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := service.Close(cleanup); err != nil {
			t.Error("native owner service did not join safely")
		}
	}()
	binding, err := manager.OwnerBinding()
	must(t, err)
	connection, err := ownerlocal.Dial(ctx, path)
	must(t, err)
	defer connection.Close()
	packet, err := manager.LocalOwnerPeer(binding)
	must(t, err)
	client, err := ownerrpc.Attach(ctx, connection, packet)
	must(t, err)
	defer client.Close()
	snapshot, err := client.Execute(ctx, ownerpacket.Command{Operation: "snapshot"})
	must(t, err)
	if snapshot.Status.Database.Err == nil || !snapshot.Status.Database.Pending || snapshot.Status.Database.Revision <= snapshot.Status.Database.SavedRevision {
		t.Fatal("service concealed failed unsaved state during authentication")
	}
	must(t, os.Remove(lockPath))
	revision := snapshot.Status.Database.Revision
	_, err = client.Execute(ctx, ownerpacket.Command{Operation: "recovery", Revision: &revision, Recovery: "retry-db"})
	must(t, err)
	_, err = client.Execute(ctx, ownerpacket.Command{Operation: "flush"})
	must(t, err)
	snapshot, err = client.Execute(ctx, ownerpacket.Command{Operation: "snapshot"})
	must(t, err)
	if snapshot.CipherDigest == ([32]byte{}) || snapshot.Status.Database.Err != nil || snapshot.Status.Database.Pending {
		t.Fatal("explicit owner retry did not save the exact pending state")
	}
	must(t, service.Close(ctx))
	select {
	case <-service.Done():
	default:
		t.Fatal("service close returned before active peer join")
	}
	if _, err := manager.Snapshot(); err != nil {
		t.Fatal("service closed its borrowed Manager")
	}
	if foreign, err := ownerlocal.Listen(path); !errors.Is(err, ownerlocal.ErrBusy) {
		if foreign != nil {
			foreign.Close()
		}
		t.Fatal("service shutdown released the parent's writer role")
	}
	must(t, manager.EditAt(snapshot.Status.Database.Revision, func(*vault.Vault) error { return nil }))
	must(t, manager.Flush(ctx))
	restarted, err := ownerservice.Start(ctx, manager)
	must(t, err)
	must(t, restarted.Close(ctx))
}

func verifyManagerRPC(t *testing.T, ctx context.Context, path string, password []byte, archive string, manager *ownerdb.Manager) {
	t.Helper()
	endpoint, err := ownerlocal.Identity(path)
	must(t, err)
	dispatcher, err := ownerdispatch.New(manager)
	must(t, err)
	var peers []*managerRPCPeer
	defer func() {
		for _, peer := range peers {
			peer.close()
		}
	}()
	attach := func() *managerRPCPeer {
		t.Helper()
		unlock, err := vault.OpenOwnerUnlock(path, password, endpoint.Binding)
		must(t, err)
		server, err := manager.OwnerPeer(endpoint.Binding)
		if err != nil {
			unlock.Close()
			t.Fatal(err)
		}
		lease, err := dispatcher.NewPeer(server.Deadline())
		if err != nil {
			server.Close()
			unlock.Close()
			t.Fatal(err)
		}
		lifetime, cancel := context.WithCancel(ctx)
		p := &managerRPCPeer{unlock: unlock, server: server, lease: lease, cancel: cancel, done: make(chan error, 1)}
		peers = append(peers, p)
		go func() {
			connection, err := manager.AcceptOwner(lifetime)
			if err != nil {
				p.done <- err
				return
			}
			p.done <- ownerrpc.ServePeer(lifetime, connection, server, lease)
		}()
		p.conn, err = ownerlocal.Dial(ctx, path)
		must(t, err)
		packet, err := unlock.Peer()
		must(t, err)
		p.client, err = ownerrpc.Attach(ctx, p.conn, packet)
		must(t, err)
		p.remote, err = ownerbackend.NewRemote(ctx, p.client)
		must(t, err)
		return p
	}
	a, b := attach(), attach()
	_, status, _, err := a.remote.OwnerSnapshot()
	must(t, err)
	must(t, a.remote.AtImportPlan(status.Database.Revision, 0).(*ownerbackend.Remote).InspectImport(archive, nil))
	must(t, a.remote.Flush(ctx))
	_, status, imported, err := b.remote.OwnerSnapshot()
	must(t, err)
	if imported.PlanID == 0 || imported.Phase != ownerdb.ImportStaged {
		t.Fatal("native remote inspection lost the exact staged plan")
	}
	before, err := manager.Snapshot()
	must(t, err)
	other := b.remote.AtImportPlan(status.Database.Revision, imported.PlanID).(*ownerbackend.Remote)
	if err := other.AbortImport(); !errors.Is(err, ownerdb.ErrPending) {
		t.Fatal("another authenticated helper adopted an active import from metadata")
	}
	change := ownerpacket.DirectoryChange{Action: "add-mcp-server", Fields: [][]byte{[]byte("rpc-owner"), []byte("https://rpc.invalid/mcp")}}
	if err := other.ApplyDirectory(change); !errors.Is(err, ownerdb.ErrPending) {
		t.Fatal("another helper mutated a directory owned by a live import")
	}
	after, err := manager.Snapshot()
	must(t, err)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("refused helper changed the import, directory, queue or receipt")
	}
	if err := a.close(); err == nil {
		t.Fatal("closed native helper unexpectedly kept a peer loop")
	}
	_, status, imported, err = b.remote.OwnerSnapshot()
	must(t, err)
	if imported.PlanID != 0 || imported.Phase != ownerdb.ImportIdle || status.Database.Revision != before.Status.Database.Revision {
		t.Fatal("native disconnect did not release only its no-effect RAM plan")
	}
	current := b.remote.AtImportPlan(status.Database.Revision, 0).(*ownerbackend.Remote)
	request, err := ownercommand.Parse([]string{"add-mcp-server", "--name", "rpc-owner", "--url", "https://rpc.invalid/mcp"}, "", "")
	must(t, err)
	model := ownertui.New(ctx, b.remote)
	defer model.ClearInput()
	must(t, model.ConfigureCommand(request))
	_, operation := model.Update(tea.KeyPressMsg{Code: 13})
	if operation == nil {
		t.Fatal("native shared form did not reach Apply")
	}
	_, finish := model.Update(operation())
	if finish == nil {
		t.Fatal("native shared form did not request persistence completion")
	}
	model.Update(finish())
	must(t, model.CommandResult())
	must(t, b.remote.Flush(ctx))
	directory, saved, _, err := b.remote.OwnerSnapshot()
	must(t, err)
	if len(directory.RemoteMCP.Servers) != 1 || directory.RemoteMCP.Servers[0].URL != "https://rpc.invalid/mcp" || saved.Database.Pending || saved.Database.SavedRevision != saved.Database.Revision {
		t.Fatal("actual Manager RPC failed to edit and save its encrypted directory")
	}
	before, err = manager.Snapshot()
	must(t, err)
	if err := current.ApplyDirectory(change); !errors.Is(err, vault.ErrOwnerRevision) {
		t.Fatal("native remote form silently adopted a newer database revision")
	}
	after, err = manager.Snapshot()
	must(t, err)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("stale remote edit changed Manager state")
	}
	must(t, b.remote.Close(ctx))
	b.close()
	if _, err := manager.Snapshot(); err != nil {
		t.Fatal("detaching helpers closed the keeper coordinator")
	}
	encoded, err := os.ReadFile(path)
	must(t, err)
	if bytes.Contains(encoded, password) || bytes.Contains(encoded, []byte("https://rpc.invalid/mcp")) {
		t.Fatal("actual Manager RPC persisted plaintext owner material")
	}
}
