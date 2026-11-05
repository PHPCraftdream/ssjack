package ownerrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func snapshotFixture() ownerdb.Snapshot {
	proxy := sshproxy.Metadata{Type: "socks5", Address: "proxy.invalid:1080", Username: "proxy-user", Authenticated: true}
	return ownerdb.Snapshot{
		Directory: vault.DirectoryMetadata{
			Servers:    []vault.ServerMetadata{{ID: "server", Name: "production", Address: "host.invalid:22", Fingerprints: []string{"SHA256:synthetic"}, Accounts: []vault.AccountMetadata{{Name: "main", Profile: "profile", User: "deploy", Authentication: "password", Usage: "both"}}, Proxy: proxy}},
			Secrets:    map[string]vault.SecretBinding{"alias": {Name: "token", ServerID: "server", Ref: "synthetic-ref"}},
			OwnerStore: &vault.OwnerStoreMetadata{Directory: "synthetic-store", StoreID: "store-id", PendingID: "pending-id", PendingPhase: "prepared"},
			RemoteMCP: mcpdirectory.Metadata{
				Servers:  []mcpdirectory.ServerMetadata{{ID: "mcp-server", Name: "remote", URL: "https://mcp.invalid/mcp", Enabled: true, Revision: 7}},
				Accounts: []mcpdirectory.AccountMetadata{{ID: "mcp-account", ServerID: "mcp-server", Name: "owner", Authentication: "basic", Username: "mcp-user", Enabled: true, CredentialSet: true, Revision: 8, HeaderNames: []string{"X-Api-Key"}}},
				Last:     map[string][]mcpdirectory.Binding{"profile": {{ServerID: "mcp-server", AccountID: "mcp-account", ServerRevision: 7, AccountRevision: 8}}},
			},
		},
		Status: ownerdb.Status{Database: vault.SessionStatus{Revision: 12, SavedRevision: 11, Pending: true}, Busy: true, Pending: true},
		Import: ownerdb.ImportStatus{
			Phase: ownerdb.ImportPartial, PlanID: 17, Published: 1, Total: 2, DirectoryApplied: true,
			Preview: vault.ImportPreview{Encrypted: true,
				Servers:   []vault.ImportServer{{ID: "import-server", Name: "imported", Address: "import.invalid:22", Fingerprints: []string{"SHA256:import"}, Accounts: []vault.ImportAccount{{Name: "import-account", User: "import-user", Authentication: "key", Usage: "agent"}}, Proxy: proxy}},
				Secrets:   []vault.ImportSecret{{AliasID: "import-alias", Name: "import-secret", ServerID: "import-server", ServerName: "imported", Length: 19}},
				Conflicts: []vault.ImportConflict{{Kind: "intrinsic", Subject: "preview"}},
			},
			Conflicts: []vault.ImportConflict{{Kind: "destination", Subject: "current"}},
		},
		CipherDigest: [32]byte{42},
	}
}

func TestSnapshotProjectionPreservesAllMetadataAndEvidence(t *testing.T) {
	for _, original := range []ownerdb.Snapshot{{}, snapshotFixture(), {Directory: vault.DirectoryMetadata{Servers: []vault.ServerMetadata{}, Secrets: map[string]vault.SecretBinding{}, RemoteMCP: mcpdirectory.Metadata{Servers: []mcpdirectory.ServerMetadata{}, Accounts: []mcpdirectory.AccountMetadata{}, Last: map[string][]mcpdirectory.Binding{}}}}} {
		encoded, err := json.Marshal(encodeSnapshot(original, nil))
		if err != nil {
			t.Fatal(err)
		}
		var reply ownerpacket.Reply
		if err := json.Unmarshal(encoded, &reply); err != nil {
			t.Fatal(err)
		}
		got, err := decodeSnapshot(reply)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatalf("snapshot metadata or persistence evidence changed: got %#v; want %#v", got, original)
		}
	}
}

func mutateReply(r *ownerpacket.Reply) {
	r.Metadata.Servers[0].Fingerprints[0] = "changed"
	r.Metadata.Servers[0].Accounts[0].User = "changed"
	r.Metadata.Secrets["alias"] = ownerpacket.Binding{}
	r.Metadata.OwnerStore.PendingID = "changed"
	r.Metadata.RemoteMCP.Servers[0].URL = "changed"
	r.Metadata.RemoteMCP.Accounts[0].HeaderNames[0] = "changed"
	r.Metadata.RemoteMCP.Last["profile"][0].AccountRevision = 99
	r.Import.Preview.Servers[0].Accounts[0].User = "changed"
	r.Import.Preview.Servers[0].Fingerprints[0] = "changed"
	r.Import.Preview.Secrets[0].Length = 99
	r.Import.Preview.Conflicts[0].Subject = "changed"
	r.Import.Conflicts[0].Subject = "changed"
}

func TestSnapshotProjectionOwnsEveryMutableBuffer(t *testing.T) {
	original := snapshotFixture()
	reply := encodeSnapshot(original, nil)
	decoded, err := decodeSnapshot(reply)
	if err != nil {
		t.Fatal(err)
	}
	mutateReply(&reply)
	if !reflect.DeepEqual(original, snapshotFixture()) || !reflect.DeepEqual(decoded, snapshotFixture()) {
		t.Fatal("wire metadata aliases manager snapshots or decoded form state")
	}
}

func TestSnapshotErrorsAreFixedCodesWithoutPrivateDiagnostics(t *testing.T) {
	private := errors.New("synthetic-private-diagnostic")
	original := snapshotFixture()
	original.Status.Err, original.Status.Database.Err, original.Import.Err = private, private, private
	reply := encodeSnapshot(original, private)
	encoded, err := json.Marshal(reply)
	if err != nil || bytes.Contains(encoded, []byte(private.Error())) {
		t.Fatal("snapshot serialized a private error diagnostic")
	}
	decoded, err := decodeSnapshot(reply)
	if !errors.Is(err, errOperation) || !errors.Is(decoded.Status.Err, errOperation) || !errors.Is(decoded.Status.Database.Err, errDatabase) || !errors.Is(decoded.Import.Err, errOperation) {
		t.Fatal("snapshot lost failure states")
	}
	for _, original := range []error{vault.ErrOwnerRevision, ownerdb.ErrPending, ownerpacket.ErrUncertain, ownerpacket.ErrAuthentication, ownerpacket.ErrProtocol} {
		wrapped := fmt.Errorf("%s: %w", private.Error(), original)
		if !errors.Is(codeError(errorCode(wrapped)), original) {
			t.Fatal("fixed code lost a typed refusal or uncertainty")
		}
	}
	if !errors.Is(codeError("unknown"), ownerpacket.ErrProtocol) {
		t.Fatal("unknown error code was treated as success")
	}
}
