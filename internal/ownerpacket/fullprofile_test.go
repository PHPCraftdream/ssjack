package ownerpacket

import (
	"bytes"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
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
	ack, err := server.Reply(Reply{Status: Status{CipherDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenReply(ack); err != nil {
		t.Fatal(err)
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
