package ownerpacket

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
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
			packet.Domain, packet.Version, packet.Command = domain, 2, &Command{Operation: "snapshot"}
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
				data = bytes.Replace(data, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1)
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

func TestImportDecisionsRequireExactlyOnePlanIdentity(t *testing.T) {
	revision := uint64(7)
	for _, command := range []Command{{Operation: "confirm-import", Revision: &revision}, {Operation: "recovery", Revision: &revision, Recovery: "resume-import"}, {Operation: "recovery", Revision: &revision, Recovery: "abort-import"}} {
		if command.valid() {
			t.Fatal("import decision omitted its displayed RAM plan")
		}
		command.Plan = 17
		if !command.valid() {
			t.Fatal("plan-scoped import decision was rejected")
		}
	}
	if (Command{Operation: "snapshot", Plan: 17}).valid() || (Command{Operation: "recovery", Revision: &revision, Recovery: "retry-db", Plan: 17}).valid() {
		t.Fatal("non-import command accepted unrelated plan authority")
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
func TestOwnerMCPExportBindingsAreBoundedExactAndExplicit(t *testing.T) {
	revision := uint64(1)
	base := Command{Operation: "export", Revision: &revision, Export: &Export{Destination: "synthetic.zip"}}
	valid := mcpdirectory.Binding{ServerID: "00000000000000000000000000000001", AccountID: "00000000000000000000000000000002", ServerRevision: 3, AccountRevision: 4}
	base.Export.RemoteMCP = []mcpdirectory.Binding{valid}
	if !base.Valid() {
		t.Fatal("explicit MCP-only export rejected")
	}
	oversized := make([]mcpdirectory.Binding, mcpdirectory.MaxAccounts+1)
	for i := range oversized {
		oversized[i] = valid
		oversized[i].AccountID = fmt.Sprintf("%032x", i+3)
	}
	for _, bindings := range [][]mcpdirectory.Binding{
		{{ServerID: "00000000000000000000000000000000", AccountID: valid.AccountID, ServerRevision: 3, AccountRevision: 4}},
		{{ServerID: valid.ServerID, AccountID: "00000000000000000000000000000000", ServerRevision: 3, AccountRevision: 4}},
		{{ServerID: valid.ServerID, AccountID: valid.AccountID, ServerRevision: 0, AccountRevision: 4}},
		{{ServerID: valid.ServerID, AccountID: valid.AccountID, ServerRevision: 3, AccountRevision: 0}},
		{valid, valid}, oversized,
		{{ServerID: "unknown-server", AccountID: valid.AccountID, ServerRevision: 3, AccountRevision: 4}},
		{{ServerID: "not-hex", AccountID: "also-not-hex", ServerRevision: 3, AccountRevision: 4}},
		nil,
	} {
		command := base
		command.Export = &Export{Destination: "synthetic.zip", RemoteMCP: bindings}
		if command.Valid() {
			t.Fatal("malformed, stale, duplicate or oversized MCP binding admitted")
		}
	}
}

// These frozen v1 helpers exercise mixed-version refusal; they are not compatibility support.
func sealV1(key box, packet envelope) ([]byte, error) {
	if key == nil {
		return nil, ErrAuthentication
	}
	packet.Domain, packet.Version = domain, 1
	plaintext, err := json.Marshal(packet)
	if err != nil || len(plaintext) == 0 || len(plaintext) > keyfile.MaxPlaintext {
		clear(plaintext)
		return nil, ErrProtocol
	}
	defer clear(plaintext)
	encoded, err := key.Seal(plaintext)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxWire {
		clear(encoded)
		return nil, ErrAuthentication
	}
	return encoded, nil
}

func openV1(key box, encoded []byte) (packet envelope, err error) {
	if key == nil || len(encoded) == 0 || len(encoded) > MaxWire {
		return packet, ErrAuthentication
	}
	plaintext, err := key.Open(encoded)
	defer clear(plaintext)
	if err != nil {
		return packet, ErrAuthentication
	}
	if len(plaintext) == 0 || len(plaintext) > keyfile.MaxPlaintext {
		return packet, ErrProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&packet) != nil {
		packet.clear()
		return envelope{}, ErrProtocol
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		packet.clear()
		return envelope{}, ErrProtocol
	}
	canonical, err := json.Marshal(packet)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plaintext) || packet.Domain != domain || packet.Version != 1 || packet.Binding == ([32]byte{}) || packet.Session == ([32]byte{}) {
		packet.clear()
		return envelope{}, ErrProtocol
	}
	return packet, nil
}

func TestApprovalChangeWireRoundTrip(t *testing.T) {
	for _, operation := range []string{"approve_application", "revoke_application"} {
		server, client, _ := unitPeers(t)
		handshake(t, server, client)
		revision := uint64(9)
		change := ApprovalChange{ApplicationName: "editor", ReviewedHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
		if operation == "approve_application" {
			change.ApplicationPath = "/opt/editor"
		} else {
			change.ReplacesHash = change.ReviewedHash
		}
		request := Command{Operation: operation, Revision: &revision, Approval: &change}
		if !request.Valid() {
			t.Fatal("valid approval command rejected")
		}
		encoded, err := client.Command(request)
		if err != nil {
			t.Fatal(err)
		}
		command, err := server.OpenCommand(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(*command, request) {
			command.Clear()
			t.Fatal("approval command changed on wire")
		}
		command.Clear()
		if *command.Approval != change {
			t.Fatal("clear changed string-only approval body")
		}
	}
}

func TestApprovalChangeRejectsOversizedPath(t *testing.T) {
	revision := uint64(1)
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	long := "/" + string(bytes.Repeat([]byte{'x'}, 512))
	edge := "/" + string(bytes.Repeat([]byte{'x'}, 511))
	approve := func(path string) Command {
		return Command{Operation: "approve_application", Revision: &revision, Approval: &ApprovalChange{ApplicationName: "editor", ApplicationPath: path, ReviewedHash: hash}}
	}
	if approve(long).valid() || !approve(edge).valid() {
		t.Fatal("approval path bound is not exactly 512 bytes")
	}
	decode := func(path string) (*Command, error, bool) {
		server, client, key := unitPeers(t)
		handshake(t, server, client)
		packet := client.peer.packet("command", "client", 1)
		packet.Domain, packet.Version = domain, protocolVersion
		command := approve(path)
		packet.Command = &command
		plaintext, err := json.Marshal(packet)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := key.Seal(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := server.OpenCommand(encoded)
		return opened, err, server.peer.closed
	}
	opened, err, closed := decode(edge)
	if err != nil || opened == nil || closed {
		t.Fatalf("512-byte approval path decode error = %v, peer closed = %v", err, closed)
	}
	opened.Clear()
	if _, err, closed := decode(long); !errors.Is(err, ErrAuthentication) || !closed {
		t.Fatalf("513-byte approval path decode error = %v, peer closed = %v", err, closed)
	}
	change := ApprovalChange{ApplicationName: "editor", ApplicationPath: "/opt/editor", ReviewedHash: hash, ReplacesHash: hash}
	if (Command{Operation: "revoke_application", Revision: &revision, Approval: &change}).valid() {
		t.Fatal("revoke with application path accepted")
	}
}

func TestApprovalChangePathCanonicalisation(t *testing.T) {
	revision := uint64(1)
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, path := range []string{"/opt/editor", "C:/opt/editor", "C:\\opt\\editor"} {
		change := ApprovalChange{ApplicationName: "editor", ApplicationPath: path, ReviewedHash: hash}
		if !(Command{Operation: "approve_application", Revision: &revision, Approval: &change}).Valid() {
			t.Errorf("canonical approval path %q rejected", path)
		}
	}
	for _, path := range []string{"/a/../b", "/a//b", "/a/", "/a/./b", "opt/editor", "/opt/\x01editor"} {
		change := ApprovalChange{ApplicationName: "editor", ApplicationPath: path, ReviewedHash: hash}
		if (Command{Operation: "approve_application", Revision: &revision, Approval: &change}).Valid() {
			t.Errorf("noncanonical approval path %q accepted", path)
		}
	}
}

func TestOwnerOperationsRejectMixedApprovalBodies(t *testing.T) {
	revision := uint64(1)
	valid := ApprovalChange{ApplicationName: "editor", ApplicationPath: "/opt/editor", ReviewedHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	rotation := Command{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "prepare", ServerID: "00000000000000000000000000000001", Account: "owner"}}
	if !rotation.valid() {
		t.Fatal("valid prepare rotation rejected")
	}
	rotation.Approval = &valid
	if rotation.valid() {
		t.Fatal("rotation command with approval body accepted")
	}
	for _, body := range []Command{
		{Directory: &DirectoryChange{}}, {Secret: &SecretChange{}}, {Export: &Export{}},
		{Link: &Link{}}, {Inspect: &Inspect{}}, {Recovery: "retry-db"}, {Rotation: &Rotation{}},
	} {
		body.Operation, body.Revision, body.Approval = "approve_application", &revision, &valid
		if body.valid() {
			t.Errorf("approval command with extra body accepted: %+v", body)
		}
	}
}

func TestApprovalOperationsRejectNonzeroPlan(t *testing.T) {
	revision := uint64(1)
	valid := ApprovalChange{ApplicationName: "editor", ApplicationPath: "/opt/editor", ReviewedHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	for _, operation := range []string{"approve_application", "revoke_application"} {
		change := valid
		if operation == "revoke_application" {
			change.ApplicationPath, change.ReplacesHash = "", change.ReviewedHash
		}
		if (Command{Operation: operation, Revision: &revision, Approval: &change, Plan: 17}).Valid() {
			t.Errorf("%s accepted nonzero plan", operation)
		}
	}
}

func TestOwnerProtocolRejectsVersion1PacketInVersion2Codec(t *testing.T) {
	server, client, key := unitPeers(t)
	handshake(t, server, client)
	revision := uint64(1)
	request := Command{Operation: "approve_application", Revision: &revision, Approval: &ApprovalChange{ApplicationName: "editor", ApplicationPath: "/opt/editor", ReviewedHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}
	packet := client.peer.packet("command", "client", 1)
	packet.Command = &request
	encoded, err := sealV1(key, packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(key, encoded); !errors.Is(err, ErrProtocol) {
		t.Fatalf("v2 open error = %v, want ErrProtocol", err)
	}

	server, client, key = unitPeers(t)
	if _, err := server.Hello(); err != nil {
		t.Fatal(err)
	}
	legacyHello, err := sealV1(key, server.peer.packet("hello", "server", 0))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.AcceptHello(legacyHello)
	if !errors.Is(err, ErrAuthentication) || len(auth) != 0 || !client.peer.closed {
		t.Fatal("v1 hello did not close the client without producing auth")
	}
	if _, err := client.Command(Command{Operation: "snapshot"}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("command after rejected hello error = %v, want ErrAuthentication", err)
	}
	// Connection closure and the keeper leaving its wait for Auth are observed in internal/ownerrpc and ownercontrol (later slices).
}

func TestOwnerProtocolRejectsVersion2PacketInVersion1Decoder(t *testing.T) {
	server, client, key := unitPeers(t)
	handshake(t, server, client)
	revision := uint64(1)
	encoded, err := client.Command(Command{Operation: "approve_application", Revision: &revision, Approval: &ApprovalChange{ApplicationName: "editor", ApplicationPath: "/opt/editor", ReviewedHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}})
	if err != nil {
		t.Fatal(err)
	}
	// This is refusal, not compatibility.
	if _, err := openV1(key, encoded); !errors.Is(err, ErrProtocol) {
		t.Fatalf("v1 open error = %v, want ErrProtocol", err)
	}
}

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
