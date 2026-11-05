package ownerpacket

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

// unitBox exercises protocol state only; public constructors require real keyfile contexts.
type unitBox struct{ cipher.AEAD }

func (b *unitBox) Seal(data []byte) ([]byte, error) {
	nonce := make([]byte, b.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.AEAD.Seal(nonce, nonce, data, nil), nil
}
func (b *unitBox) Open(data []byte) ([]byte, error) {
	if len(data) < b.NonceSize() {
		return nil, ErrAuthentication
	}
	return b.AEAD.Open(nil, data[:b.NonceSize()], data[b.NonceSize():], nil)
}
func unitPeers(t *testing.T) (*Server, *Client, *unitBox) {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	key := &unitBox{aead}
	session, err := nonce()
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{peer: peer{key: key, binding: [32]byte{1}, session: session, digest: [32]byte{2}, expires: time.Now().Add(Lease), sequence: 1, now: time.Now}}
	client := &Client{peer: peer{key: key, binding: [32]byte{1}, sequence: 1, now: time.Now}}
	return server, client, key
}
func handshake(t *testing.T, server *Server, client *Client) {
	t.Helper()
	hello, err := server.Hello()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.AcceptHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := server.Authenticate(auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptReady(ready); err != nil {
		t.Fatal(err)
	}
}
func TestOwnerMutualAuthenticationAndFinalSequenceReply(t *testing.T) {
	server, client, _ := unitPeers(t)
	handshake(t, server, client)
	server.peer.sequence, client.peer.sequence = MaxMessages, MaxMessages
	revision := uint64(0)
	request := Command{Operation: "secret", Revision: &revision, Secret: &SecretChange{Action: "add", Name: "token", Value: []byte("synthetic-private-owner-value"), MediaType: "text/plain"}}
	encoded, err := client.Command(request)
	if err != nil || bytes.Contains(encoded, request.Secret.Value) {
		t.Fatal("request was not encrypted")
	}
	command, err := server.OpenCommand(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer command.Clear()
	if !bytes.Equal(command.Secret.Value, request.Secret.Value) {
		t.Fatal("owner request changed")
	}
	ack, err := server.Reply(Reply{Status: Status{Revision: 1, SavedRevision: 1, CipherDigest: [32]byte{3}}})
	if err != nil {
		t.Fatal("last admitted command lost its reply")
	}
	reply, err := client.OpenReply(ack)
	if err != nil || reply.Status.Revision != 1 {
		t.Fatal("last completion evidence was lost")
	}
	if _, err := client.Command(Command{Operation: "snapshot"}); err == nil {
		t.Fatal("message budget silently renewed")
	}
}
func TestOwnerProtocolRefusesReplayReflectionCrossBindingAndMalformedPayload(t *testing.T) {
	for _, mode := range []string{"domain", "binding", "session", "client", "digest", "sequence", "direction", "operation", "mixed", "duplicate", "unknown", "trailing", "tamper", "expired"} {
		t.Run(mode, func(t *testing.T) {
			server, client, key := unitPeers(t)
			handshake(t, server, client)
			packet := client.peer.packet("command", "client", 1)
			packet.Domain, packet.Version, packet.Command = domain, 1, &Command{Operation: "snapshot"}
			switch mode {
			case "domain":
				packet.Domain = "storage"
			case "binding":
				packet.Binding[0]++
			case "session":
				packet.Session[0]++
			case "client":
				packet.Client[0]++
			case "digest":
				packet.Digest[0]++
			case "sequence":
				packet.Sequence++
			case "direction":
				packet.Direction = "server"
			case "operation":
				packet.Command.Operation = "get-secret"
			case "mixed":
				packet.Reply = &Reply{}
			case "expired":
				server.peer.now = func() time.Time { return server.peer.expires.Add(time.Second) }
			}
			data, err := json.Marshal(packet)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "duplicate":
				data = bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
			case "unknown":
				data = append(data[:len(data)-1], []byte(`,"unknown":true}`)...)
			case "trailing":
				data = append(data, []byte(`{}`)...)
			}
			encoded, err := key.Seal(data)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "tamper" {
				encoded[len(encoded)-1] ^= 1
			}
			if command, err := server.OpenCommand(encoded); err == nil {
				command.Clear()
				t.Fatal("invalid owner packet admitted an operation")
			}
			if !server.peer.closed {
				t.Fatal("rejected packet left the channel reusable")
			}
		})
	}
	server, client, _ := unitPeers(t)
	handshake(t, server, client)
	encoded, err := client.Command(Command{Operation: "snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	if command, err := server.OpenCommand(encoded); err != nil {
		t.Fatal(err)
	} else {
		command.Clear()
	}
	if _, err := server.Reply(Reply{}); err != nil {
		t.Fatal(err)
	}
	if command, err := server.OpenCommand(encoded); err == nil {
		command.Clear()
		t.Fatal("completed request replay was admitted")
	}
}
func TestOwnerProtocolRejectsUnauthenticatedAndReplayedHandshake(t *testing.T) {
	server, client, _ := unitPeers(t)
	if _, err := client.Command(Command{Operation: "snapshot"}); err == nil {
		t.Fatal("unauthenticated client sent a command")
	}
	server, client, _ = unitPeers(t)
	hello, err := server.Hello()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.AcceptHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := unitPeers(t)
	if _, err := other.Hello(); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Authenticate(auth); err == nil {
		t.Fatal("authentication replay crossed owner sessions")
	}
	ready, err := server.Authenticate(auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptReady(ready); err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptReady(ready); err == nil {
		t.Fatal("ready acknowledgement replay was accepted")
	}
}

type frameConnection struct {
	bytes.Buffer
	reads, writes int
	writeError    bool
}

func (c *frameConnection) Read(_ context.Context, p []byte) (int, error) {
	c.reads++
	return c.Buffer.Read(p)
}
func (c *frameConnection) Write(_ context.Context, p []byte) (int, error) {
	c.writes++
	if c.writeError {
		return 0, io.ErrClosedPipe
	}
	return c.Buffer.Write(p)
}
func (c *frameConnection) Close() error { return nil }
func TestOwnerMCPReplyBounds(t *testing.T) {
	for _, metadata := range []mcpdirectory.Metadata{
		{Servers: make([]mcpdirectory.ServerMetadata, 33)},
		{Accounts: make([]mcpdirectory.AccountMetadata, 65)},
		{Accounts: []mcpdirectory.AccountMetadata{{HeaderNames: make([]string, 5)}}},
		{Last: map[string][]mcpdirectory.Binding{"profile": make([]mcpdirectory.Binding, 17)}},
	} {
		if (Reply{Metadata: Metadata{RemoteMCP: metadata}}).valid() {
			t.Fatal("owner reply accepted oversized MCP metadata")
		}
	}
	last := make(map[string][]mcpdirectory.Binding)
	for i := 0; i < 65; i++ {
		last[string(rune(i))] = nil
	}
	if (Reply{Metadata: Metadata{RemoteMCP: mcpdirectory.Metadata{Last: last}}}).valid() {
		t.Fatal("owner reply accepted too many remembered MCP contexts")
	}
	bounded := mcpdirectory.Metadata{Servers: make([]mcpdirectory.ServerMetadata, 32), Accounts: make([]mcpdirectory.AccountMetadata, 64)}
	if !(Reply{Metadata: Metadata{RemoteMCP: bounded}}).valid() {
		t.Fatal("owner reply rejected bounded MCP metadata")
	}
}

func TestOwnerFramesRefuseBoundsBeforeBodyAndNeverRetryWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, size := range []uint32{0, MaxWire + 1} {
		connection := &frameConnection{}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		connection.Buffer.Write(header[:])
		if _, err := ReadFrame(ctx, connection); err == nil || connection.reads != 1 {
			t.Fatal("invalid owner frame allocated/read a body")
		}
	}
	connection := &frameConnection{writeError: true}
	if err := WriteFrame(ctx, connection, []byte("ciphertext")); !errors.Is(err, ErrUncertain) || connection.writes != 1 {
		t.Fatal("failed owner write was retried or called complete")
	}
	if _, err := ReadFrame(context.Background(), connection); err == nil || connection.reads != 0 {
		t.Fatal("unbounded read context was accepted")
	}
}
