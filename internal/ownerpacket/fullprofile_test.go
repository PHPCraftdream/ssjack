package ownerpacket

import (
	"bytes"
	"crypto/sha256"
	"os"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

func TestOwnerPacketFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production owner IPC crypto runs only in dedicated GitHub CI")
	}
	password := []byte("synthetic owner channel profile")
	defer clear(password)
	serverKey, err := keyfile.NewUnlocked(password, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer serverKey.Close()
	stored, err := serverKey.Seal([]byte("synthetic authenticated database payload"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, clientKey, err := keyfile.Unlock(stored, password)
	if err != nil {
		t.Fatal(err)
	}
	clear(plaintext)
	defer clientKey.Close()
	binding, digest := [32]byte{1}, sha256.Sum256(stored)
	server, err := NewServer(serverKey, binding, digest)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(clientKey, binding)
	if err != nil {
		t.Fatal(err)
	}
	handshake(t, server, client)
	if command, err := server.OpenCommand(stored); err == nil {
		command.Clear()
		t.Fatal("storage ciphertext was admitted as an owner command")
	}
	server, err = NewServer(serverKey, binding, digest)
	if err != nil {
		t.Fatal(err)
	}
	client, err = NewClient(clientKey, binding)
	if err != nil {
		t.Fatal(err)
	}
	handshake(t, server, client)
	revision := uint64(0)
	value := []byte("synthetic private IPC value")
	defer clear(value)
	expected := append([]byte(nil), value...)
	defer clear(expected)
	request := Command{Operation: "secret", Revision: &revision, Secret: &SecretChange{Action: "add", Name: "token", Value: value, MediaType: "text/plain"}}
	encoded, err := client.Command(request)
	if err != nil || bytes.Contains(encoded, value) || bytes.Contains(encoded, password) {
		t.Fatal("owner request encryption exposed private input")
	}
	command, err := server.OpenCommand(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(command.Secret.Value, value) {
		t.Fatal("production IPC changed the owner value")
	}
	owned := command.Secret.Value
	command.Clear()
	if !bytes.Equal(owned, make([]byte, len(owned))) || !bytes.Equal(value, expected) {
		t.Fatal("owner command ownership or clearing changed")
	}
	mcp := mcpdirectory.Metadata{
		Servers:  []mcpdirectory.ServerMetadata{{ID: "synthetic-server", Name: "remote", URL: "https://mcp.invalid/mcp", Enabled: true, Revision: 3}},
		Accounts: []mcpdirectory.AccountMetadata{{ID: "synthetic-account", ServerID: "synthetic-server", Name: "owner", Authentication: "bearer", Enabled: true, CredentialSet: true, Revision: 4, HeaderNames: []string{"X-Api-Key"}}},
		Last:     map[string][]mcpdirectory.Binding{"synthetic-profile": {{ServerID: "synthetic-server", AccountID: "synthetic-account", ServerRevision: 3, AccountRevision: 4}}},
	}
	ack, err := server.Reply(Reply{Status: Status{CipherDigest: digest}, Metadata: Metadata{RemoteMCP: mcp}})
	if err != nil || bytes.Contains(ack, []byte(mcp.Servers[0].URL)) {
		t.Fatal("production reply did not encrypt owner MCP metadata")
	}
	reply, err := client.OpenReply(ack)
	if err != nil || !reflect.DeepEqual(reply.Metadata.RemoteMCP, mcp) || reply.Status.CipherDigest != digest {
		t.Fatal("production reply lost MCP metadata or persistence evidence")
	}
	planCommand, err := client.Command(Command{Operation: "confirm-import", Revision: &revision, Plan: 17})
	if err != nil {
		t.Fatal("production client rejected a plan-scoped decision")
	}
	openedPlan, err := server.OpenCommand(planCommand)
	if err != nil || openedPlan == nil || openedPlan.Plan != 17 {
		t.Fatal("production request lost its authenticated RAM plan identity")
	}
	openedPlan.Clear()
	planReply, err := server.Reply(Reply{Import: ImportStatus{Phase: "staged", PlanID: 17}})
	if err != nil {
		t.Fatal(err)
	}
	projectedPlan, err := client.OpenReply(planReply)
	if err != nil || projectedPlan.Import.PlanID != 17 {
		t.Fatal("production reply lost its authenticated RAM plan identity")
	}
	otherKey, err := keyfile.NewUnlocked(password, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer otherKey.Close()
	other, err := NewClient(otherKey, binding)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewServer(serverKey, binding, digest)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := fresh.Hello()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.AcceptHello(hello); err == nil {
		t.Fatal("same password from another database context authenticated")
	}
	clientKey.Close()
	if _, err := client.Command(Command{Operation: "snapshot"}); err == nil {
		t.Fatal("closed owner unlock remained usable")
	}
	if _, err := serverKey.Seal([]byte("database context remains live")); err != nil {
		t.Fatal("helper close also closed the coordinator context")
	}
}
