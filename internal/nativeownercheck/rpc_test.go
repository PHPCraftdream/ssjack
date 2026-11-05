package nativeownercheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrpc"
)

type rpcHandler struct {
	calls atomic.Int32
	value []byte
	reply ownerpacket.Reply
}

func (h *rpcHandler) Dispatch(ctx context.Context, command *ownerpacket.Command) ownerpacket.Reply {
	h.calls.Add(1)
	if ctx.Err() != nil || command.Secret == nil || !bytes.Equal(command.Secret.Value, h.value) || command.Revision == nil || *command.Revision != 7 {
		return ownerpacket.Reply{ErrorCode: "invalid"}
	}
	return h.reply
}

func verifyOwnerRPC(t *testing.T, ctx context.Context) {
	t.Helper()
	password := []byte("synthetic native owner RPC password")
	defer clear(password)
	serverKey, err := keyfile.NewUnlocked(password, 2)
	must(t, err)
	defer serverKey.Close()
	stored, err := serverKey.Seal([]byte("synthetic owner RPC database payload"))
	must(t, err)
	plaintext, clientKey, err := keyfile.Unlock(stored, password)
	must(t, err)
	clear(plaintext)
	defer clientKey.Close()
	path := filepath.Join(t.TempDir(), "owner-rpc.ktav")
	must(t, os.WriteFile(path, stored, 0600))
	endpoint, err := ownerlocal.Identity(path)
	must(t, err)
	listener, err := ownerlocal.Listen(path)
	must(t, err)
	defer listener.Close()
	serverPeer, err := ownerpacket.NewServer(serverKey, endpoint.Binding, sha256.Sum256(stored))
	must(t, err)
	defer serverPeer.Close()
	value := []byte("synthetic native private RPC command value")
	defer clear(value)
	handler := &rpcHandler{value: value, reply: ownerpacket.Reply{
		Metadata: ownerpacket.Metadata{RemoteMCP: mcpdirectory.Metadata{
			Servers:  []mcpdirectory.ServerMetadata{{ID: "synthetic-server", Name: "remote", URL: "https://mcp.invalid/mcp", Enabled: true, Revision: 3}},
			Accounts: []mcpdirectory.AccountMetadata{{ID: "synthetic-account", ServerID: "synthetic-server", Name: "main", Authentication: "bearer", CredentialSet: true, Enabled: true, Revision: 4}},
			Last:     map[string][]mcpdirectory.Binding{"synthetic-profile": {{ServerID: "synthetic-server", AccountID: "synthetic-account", ServerRevision: 3, AccountRevision: 4}}},
		}}, Status: ownerpacket.Status{Revision: 8, SavedRevision: 8, CipherDigest: sha256.Sum256(stored)},
	}}
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(lifetime)
		if err != nil {
			done <- err
			return
		}
		done <- ownerrpc.ServePeer(lifetime, connection, serverPeer, handler)
	}()
	// Every failure joins the peer before either borrowed key closes.
	defer func() {
		cancel()
		listener.Close()
		if err := <-done; err == nil {
			t.Error("closed native owner RPC unexpectedly retained its peer loop")
		}
	}()
	connection, err := ownerlocal.Dial(ctx, path)
	must(t, err)
	defer connection.Close()
	clientPeer, err := ownerpacket.NewClient(clientKey, endpoint.Binding)
	must(t, err)
	defer clientPeer.Close()
	client, err := ownerrpc.Attach(ctx, connection, clientPeer)
	must(t, err)
	defer client.Close()
	revision := uint64(7)
	command := ownerpacket.Command{Operation: "secret", Revision: &revision, Secret: &ownerpacket.SecretChange{Action: "add", Name: "token", Value: value, MediaType: "text/plain"}}
	reply, err := client.Call(ctx, command)
	must(t, err)
	if !reflect.DeepEqual(reply, handler.reply) || handler.calls.Load() != 1 {
		t.Fatal("native authenticated RPC changed metadata, dispatched twice or lost its receipt")
	}
	client.Close()
	if _, err := client.Call(ctx, command); !errors.Is(err, ownerpacket.ErrAuthentication) || handler.calls.Load() != 1 {
		t.Fatal("closed native RPC replayed a mutation")
	}
	if _, err := serverKey.Seal([]byte("parent context remains live")); err != nil {
		t.Fatal("closing an RPC peer closed its borrowed parent context")
	}
}
