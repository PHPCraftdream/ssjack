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
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
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
				RemoteMCP: mcpdirectory.Metadata{Servers: []mcpdirectory.ServerMetadata{{ID: "preview-server", Name: "preview", URL: "https://preview.invalid/mcp", Enabled: false, Revision: 1}}, Accounts: []mcpdirectory.AccountMetadata{{ID: "preview-account", ServerID: "preview-server", Name: "disabled", Authentication: "bearer", Enabled: false, Revision: 1}}},
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
	r.Import.Preview.RemoteMCP.Servers[0].URL = "changed"
	r.Import.Preview.RemoteMCP.Accounts[0].Name = "changed"
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

func TestSnapshotRotationRoundTripAndCloning(t *testing.T) {
	rotation := vault.RotationInfo{
		ID: "0102030405060708090a0b0c0d0e0f10", Phase: vault.RotationComplete,
		ServerID: "101112131415161718191a1b1c1d1e1f", Account: "main", Profile: "profile",
		PlanID: 9, BaseRevision: 7, CommitRevision: 0,
		CommitDigest: "0101010101010101010101010101010101010101010101010101010101010101",
		OldPublic:    []byte("old-public"), NewPublic: []byte("new-public"), HostKeys: []string{"SHA256:synthetic"},
	}
	want := rotation
	want.OldPublic = append([]byte(nil), rotation.OldPublic...)
	want.NewPublic = append([]byte(nil), rotation.NewPublic...)
	want.HostKeys = append([]string(nil), rotation.HostKeys...)
	original := ownerdb.Snapshot{
		Rotation: &rotation, CipherDigest: [32]byte{42},
		Status: ownerdb.Status{Database: vault.SessionStatus{Revision: 0, SavedRevision: 0}},
	}
	reply := encodeSnapshot(original, nil)
	rotation.OldPublic[0], rotation.NewPublic[0], rotation.HostKeys[0] = 'X', 'Y', "changed"
	if reply.Rotation == nil || !bytes.Equal(reply.Rotation.OldPublic, want.OldPublic) || !bytes.Equal(reply.Rotation.NewPublic, want.NewPublic) || !reflect.DeepEqual(reply.Rotation.HostKeys, want.HostKeys) {
		t.Fatal("encoded rotation metadata aliases the source snapshot")
	}
	encoded, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &reply); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSnapshot(reply)
	if err != nil || decoded.Rotation == nil || !reflect.DeepEqual(*decoded.Rotation, want) {
		t.Fatalf("rotation metadata changed during round-trip: got %#v, want %#v (err %v)", decoded.Rotation, want, err)
	}
	if decoded.Status.Database.Revision != 0 || decoded.Status.Database.SavedRevision != 0 || decoded.CipherDigest != original.CipherDigest || decoded.Rotation.BaseRevision != 7 || decoded.Rotation.CommitRevision != 0 || decoded.Rotation.CommitDigest != want.CommitDigest {
		t.Fatal("round-trip lost the saved digest or retained completed-rotation proof")
	}
	reply.Rotation.OldPublic[0], reply.Rotation.NewPublic[0], reply.Rotation.HostKeys[0] = 'X', 'Y', "changed"
	if !reflect.DeepEqual(*decoded.Rotation, want) {
		t.Fatal("decoded rotation metadata aliases the reply")
	}
}

func TestSnapshotArchivedRotationRoundTripAndImmutableRecoveryMetadata(t *testing.T) {
	rotation := vault.RotationInfo{
		ID: "0102030405060708090a0b0c0d0e0f10", Phase: vault.RotationArchived,
		ServerID: "101112131415161718191a1b1c1d1e1f", Account: "main", Profile: "profile",
		PlanID: 9, BaseRevision: 7, CommitRevision: 0,
		CommitDigest: "0101010101010101010101010101010101010101010101010101010101010101",
		RecoveryPath: "rotation-recovery.vault", RecoveryDigest: "0202020202020202020202020202020202020202020202020202020202020202",
	}
	original := ownerdb.Snapshot{Rotation: &rotation, CipherDigest: [32]byte{42}}
	reply := encodeSnapshot(original, nil)
	rotation.RecoveryPath, rotation.RecoveryDigest = "mutated-source", "mutated-digest"
	if reply.Rotation == nil || reply.Rotation.RecoveryPath != "rotation-recovery.vault" || reply.Rotation.RecoveryDigest != "0202020202020202020202020202020202020202020202020202020202020202" {
		t.Fatal("encoded archive metadata changed with its source snapshot")
	}
	encoded, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(`"old_public"`), []byte(`"new_public"`), []byte(`"host_keys"`), []byte(`"address"`), []byte(`"user"`), []byte(`"usage"`)} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("archived snapshot serialized forbidden metadata field %s", forbidden)
		}
	}
	if err := json.Unmarshal(encoded, &reply); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSnapshot(reply)
	if err != nil || decoded.Rotation == nil || decoded.Rotation.RecoveryPath != "rotation-recovery.vault" || decoded.Rotation.RecoveryDigest != "0202020202020202020202020202020202020202020202020202020202020202" || decoded.Rotation.CommitRevision != 0 {
		t.Fatalf("archived metadata changed during round-trip: %#v (err %v)", decoded.Rotation, err)
	}
	reply.Rotation.RecoveryPath, reply.Rotation.RecoveryDigest = "mutated-reply", "mutated-reply-digest"
	if decoded.Rotation.RecoveryPath != "rotation-recovery.vault" || decoded.Rotation.RecoveryDigest != "0202020202020202020202020202020202020202020202020202020202020202" {
		t.Fatal("decoded archive metadata aliases the reply strings")
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
	for _, original := range []error{vault.ErrOwnerRevision, ownerdb.ErrPending, ownerpacket.ErrUncertain, ownerpacket.ErrAuthentication, ownerpacket.ErrProtocol, ownerrotation.ErrUncertain} {
		wrapped := fmt.Errorf("%s: %w", private.Error(), original)
		if original == ownerrotation.ErrUncertain {
			if code := errorCode(wrapped); code != "rotation-uncertain" || !errors.Is(codeError(code), ownerrotation.ErrUncertain) {
				t.Fatal("rotation uncertainty did not preserve its distinct fixed wire code")
			}
			continue
		}
		if !errors.Is(codeError(errorCode(wrapped)), original) {
			t.Fatal("snapshot code projection changed the existing typed refusal")
		}
	}
	if !errors.Is(codeError("unknown"), ownerpacket.ErrProtocol) {
		t.Fatal("unknown error code was treated as success")
	}
}

func TestSnapshotSSHStatusRoundTripAndCloning(t *testing.T) {
	cases := []struct {
		name   string
		status sshstatus.Status
	}{
		{name: "known-zero", status: sshstatus.Status{Profile: "profile", DesiredKnown: true, DeliveredKnown: true, AdoptedKnown: true}},
		{name: "unknown-zero", status: sshstatus.Status{Profile: "profile"}},
		{name: "not-adopted-zero", status: sshstatus.Status{Profile: "profile", DesiredKnown: true, DeliveredKnown: true}},
		{name: "revisions", status: sshstatus.Status{Profile: "profile", DesiredRevision: 41, DesiredKnown: true, DeliveredRevision: 40, DeliveredKnown: true, AdoptedRevision: 39, AdoptedKnown: true, Unavailable: true}},
	}
	encoders := []struct {
		name string
		fn   func(ownerdb.Snapshot, error) ownerpacket.Reply
	}{
		{name: "SnapshotReply", fn: SnapshotReply},
		{name: "encodeSnapshot", fn: encodeSnapshot},
	}
	for _, test := range cases {
		for _, encoder := range encoders {
			t.Run(test.name+"/"+encoder.name, func(t *testing.T) {
				owned := test.status
				expected := owned
				original := ownerdb.Snapshot{}
				original.Status.Database.SSH = &owned
				reply := encoder.fn(original, nil)
				owned = sshstatus.Status{Profile: "mutated-original"}
				if reply.Status.SSH == nil || !reflect.DeepEqual(*reply.Status.SSH, expected) {
					t.Fatal("encoded reply did not preserve an independent SSH status value")
				}
				decoded, err := decodeSnapshot(reply)
				if err != nil || decoded.Status.Database.SSH == nil || !reflect.DeepEqual(*decoded.Status.Database.SSH, expected) {
					t.Fatalf("decoded SSH status changed: got %#v, want %#v (err %v)", decoded.Status.Database.SSH, expected, err)
				}
				*reply.Status.SSH = sshstatus.Status{Profile: "mutated-reply"}
				if !reflect.DeepEqual(*decoded.Status.Database.SSH, expected) {
					t.Fatal("decoded snapshot aliases the reply SSH status")
				}
			})
		}
	}
}

func TestSnapshotSSHStatusUsesFixedMetadataShape(t *testing.T) {
	packetField, ok := reflect.TypeOf(ownerpacket.Status{}).FieldByName("SSH")
	if !ok || packetField.Type != reflect.TypeOf((*sshstatus.Status)(nil)) {
		t.Fatal("owner packet SSH status is not a status-only pointer")
	}
	wantFields := []string{"Profile", "DesiredRevision", "DesiredKnown", "DeliveredRevision", "DeliveredKnown", "AdoptedRevision", "AdoptedKnown", "Unavailable"}
	statusType := reflect.TypeOf(sshstatus.Status{})
	if statusType.NumField() != len(wantFields) {
		t.Fatalf("SSH status shape has %d fields, want %d fixed metadata fields", statusType.NumField(), len(wantFields))
	}
	for i, want := range wantFields {
		if got := statusType.Field(i).Name; got != want {
			t.Fatalf("SSH status field %d is %q, want %q", i, got, want)
		}
	}
}
