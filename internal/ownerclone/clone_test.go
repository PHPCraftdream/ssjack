package ownerclone

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestLinkAndIntentCopiesRetainIdentityAndOwnPrivateBuffers(t *testing.T) {
	original := &vault.OwnerStore{
		Directory: "synthetic-store", StoreID: "store", Master: []byte("synthetic-master"),
		Pending: &vault.OwnerIntent{ID: "intent", Phase: "prepared", TransactionID: "transaction", SnapshotID: "snapshot", PreviousStateHash: "previous", Versions: map[string]string{"object": "version"}, Change: vault.OwnerChange{Action: "add", AliasID: "alias", Name: "token", ServerID: "server", ObjectID: "object", PreviousReference: "reference", MediaType: "text/plain", Value: []byte("synthetic-private-value")}},
	}
	copied := Link(original)
	if !reflect.DeepEqual(copied, original) || !reflect.DeepEqual(Intent(original.Pending), original.Pending) {
		t.Fatal("copy changed owner identity, intent, versions or private input")
	}
	copied.Pending.Versions["object"] = "changed"
	copied.Directory = "changed"
	ClearLink(copied)
	if original.Directory != "synthetic-store" || original.Pending.Versions["object"] != "version" || string(original.Master) != "synthetic-master" || string(original.Pending.Change.Value) != "synthetic-private-value" {
		t.Fatal("owned copy or clear changed the original owner state")
	}
	if !bytes.Equal(copied.Master, make([]byte, len(copied.Master))) || !bytes.Equal(copied.Pending.Change.Value, make([]byte, len(copied.Pending.Change.Value))) {
		t.Fatal("clear retained copied private bytes")
	}
	ClearLink(original)
}

func TestPreviewCopyOwnsAllNestedDisplayBuffers(t *testing.T) {
	original := vault.ImportPreview{Encrypted: true,
		Servers:   []vault.ImportServer{{ID: "server", Name: "production", Address: "synthetic.invalid:22", Fingerprints: []string{"synthetic-pin"}, Accounts: []vault.ImportAccount{{Name: "main", User: "deploy", Authentication: "password", Usage: "both"}}}},
		Secrets:   []vault.ImportSecret{{AliasID: "alias", Name: "token", ServerID: "server", ServerName: "production", Length: 11}},
		Conflicts: []vault.ImportConflict{{Kind: "synthetic", Subject: "conflict"}},
	}
	copied := Preview(original)
	if !reflect.DeepEqual(copied, original) {
		t.Fatal("preview copy changed metadata")
	}
	copied.Servers[0].Fingerprints[0] = "changed"
	copied.Servers[0].Accounts[0].User = "changed"
	copied.Secrets[0].Length = 99
	copied.Conflicts[0].Subject = "changed"
	if original.Servers[0].Fingerprints[0] != "synthetic-pin" || original.Servers[0].Accounts[0].User != "deploy" || original.Secrets[0].Length != 11 || original.Conflicts[0].Subject != "conflict" {
		t.Fatal("preview copy aliases caller-owned metadata")
	}
}

func TestCopyNilAndEmptySemanticsRemainUnchanged(t *testing.T) {
	if Link(nil) != nil || Intent(nil) != nil {
		t.Fatal("nil owner state became an allocated record")
	}
	ClearLink(nil)
	link := Link(&vault.OwnerStore{})
	if link.Master != nil || link.Pending != nil {
		t.Fatal("empty link changed its nil private fields")
	}
	intent := Intent(&vault.OwnerIntent{})
	if intent.Change.Value == nil || len(intent.Change.Value) != 0 || intent.Versions == nil || len(intent.Versions) != 0 {
		t.Fatal("empty intent lost its existing allocated-empty copy semantics")
	}
	preview := Preview(vault.ImportPreview{})
	if preview.Servers == nil || preview.Secrets == nil || preview.Conflicts == nil {
		t.Fatal("empty preview lost its existing allocated-empty copy semantics")
	}
}
