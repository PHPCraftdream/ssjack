package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"sync/atomic"
	"testing"
)

func TestSessionMetadataOwnsCollectionsAndOmitsPrivateMaterial(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	alias, err := v.BindSecret("", SecretBinding{Name: "existing", Ref: directoryRef(t, 3)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "pending", MediaType: "text/plain", Value: []byte("synthetic pending private value")}); err != nil {
		t.Fatal(err)
	}
	var saves atomic.Int32
	s := newSession(v, func(context.Context, []byte) error { saves.Add(1); return nil }, func() {})
	defer s.Discard()
	metadata, err := s.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Servers) != 1 || len(metadata.Servers[0].Accounts) != 1 || metadata.Servers[0].Accounts[0].Authentication != "key" || metadata.Secrets[alias].Name != "existing" || metadata.OwnerStore == nil || metadata.OwnerStore.PendingPhase != "draft" {
		t.Fatal("display metadata omitted the expected safe context")
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range [][]byte{v.Targets["production"].PrivateKey, v.OwnerStore.Master, v.OwnerStore.Pending.Change.Value} {
		if bytes.Contains(encoded, private) || bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(private))) {
			t.Fatal("display metadata exposed private material")
		}
	}
	metadata.Servers[0].Name = "caller-mutated"
	metadata.Servers[0].Accounts[0].User = "caller-mutated"
	metadata.Servers[0].Fingerprints[0] = "caller-mutated"
	metadata.Secrets[alias] = SecretBinding{}
	metadata.OwnerStore.PendingPhase = "caller-mutated"
	again, err := s.Metadata()
	if err != nil || again.Servers[0].Name != "production" || again.Servers[0].Accounts[0].User == "caller-mutated" || again.Servers[0].Fingerprints[0] == "caller-mutated" || again.Secrets[alias].Name != "existing" || again.OwnerStore.PendingPhase != "draft" || saves.Load() != 0 {
		t.Fatal("read-only metadata mutated the database, leaked collections, or queued persistence")
	}
}
