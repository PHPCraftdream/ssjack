package vault

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func ownerID(value byte) string {
	id := [16]byte{value}
	return hex.EncodeToString(id[:])
}

func ownerReference(t *testing.T, object, version, snapshot byte) appstoreref.Ref {
	t.Helper()
	reference, err := appstoreref.New([16]byte{1}, [16]byte{object}, [16]byte{version}, [16]byte{snapshot})
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func ownerReferenceText(t *testing.T, reference appstoreref.Ref) string {
	t.Helper()
	text, err := appstoreplaceholder.Encode(reference)
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

func ownerStoreFixture(t *testing.T) (*Vault, string) {
	t.Helper()
	v, server := directoryFixture(t)
	master := []byte("synthetic linked-store master")
	if err := v.LinkOwnerStore(OwnerStore{Directory: t.TempDir(), StoreID: ownerID(1), Master: master}); err != nil {
		t.Fatal(err)
	}
	clear(master)
	if !bytes.Equal(v.OwnerStore.Master, []byte("synthetic linked-store master")) {
		t.Fatal("owner-store link borrowed the input master buffer")
	}
	return v, server
}

func TestOwnerStoreDraftRoundtripAndCleanup(t *testing.T) {
	v, server := ownerStoreFixture(t)
	value := []byte("synthetic pending value")
	operation, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "token", ServerID: server, MediaType: "text/plain", Value: value})
	if err != nil {
		t.Fatal(err)
	}
	clear(value)
	if v.OwnerStore.Pending.ID != operation || v.OwnerStore.Pending.Phase != "draft" || len(v.Secrets) != 0 || !bytes.Equal(v.OwnerStore.Pending.Change.Value, []byte("synthetic pending value")) {
		t.Fatal("draft changed aliases or lost its owned value")
	}
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v.OwnerStore, decoded.OwnerStore) {
		decoded.Close()
		t.Fatal("owner-store draft changed during roundtrip")
	}
	master, pending := decoded.OwnerStore.Master, decoded.OwnerStore.Pending.Change.Value
	decoded.Close()
	if !bytes.Equal(master, make([]byte, len(master))) || !bytes.Equal(pending, make([]byte, len(pending))) {
		t.Fatal("owner unlock material or pending input was not cleared")
	}
	if _, err := v.BindSecret("", SecretBinding{Name: "racing", Ref: directoryRef(t, 3)}); err == nil {
		t.Fatal("a binding edit raced with a pending owner operation")
	}
	if err := v.RenameServer(server, "renamed-server"); err != nil {
		t.Fatal("unrelated server metadata could not be edited")
	}
	pending = v.OwnerStore.Pending.Change.Value
	if err := v.CancelOwnerDraft(operation); err != nil || v.OwnerStore.Pending != nil || !bytes.Equal(pending, make([]byte, len(pending))) {
		t.Fatal("cancelling a pre-dispatch draft did not clear its private input")
	}
}

func TestOwnerStoreProposalAndReceiptPreserveUnrelatedAliases(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	old := ownerReferenceText(t, ownerReference(t, 2, 3, 4))
	selected, err := v.BindSecret("", SecretBinding{Name: "token", Ref: old})
	if err != nil {
		t.Fatal(err)
	}
	other, err := v.BindSecret("", SecretBinding{Name: "other", Ref: ownerReferenceText(t, ownerReference(t, 9, 10, 4))})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := v.StageOwnerChange(OwnerChange{Action: "update", AliasID: selected, Name: "renamed", PreviousReference: old, MediaType: "text/plain", Value: []byte("new synthetic value")})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), map[string]string{ownerID(2): ownerID(5)}); err == nil || v.OwnerStore.Pending.Phase != "draft" {
		t.Fatal("proposal dropped an unrelated alias or mutated a refused draft")
	}
	versions := map[string]string{ownerID(2): ownerID(5), ownerID(9): ownerID(6)}
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), versions); err != nil {
		t.Fatal(err)
	}
	versions[ownerID(2)] = ownerID(99)
	if v.OwnerStore.Pending.Versions[ownerID(2)] != ownerID(5) {
		t.Fatal("prepared version map borrowed caller storage")
	}
	if err := v.CancelOwnerDraft(operation); err == nil {
		t.Fatal("prepared intent was erased without reconciliation")
	}
	references := []appstoreref.Ref{ownerReference(t, 2, 5, 7), ownerReference(t, 9, 6, 7)}
	if err := v.FinishOwnerChange(operation, ownerID(99), ownerID(7), references); err == nil || v.Secrets[selected].Ref != old {
		t.Fatal("mismatched receipt changed aliases")
	}
	pending := v.OwnerStore.Pending.Change.Value
	if err := v.FinishOwnerChange(operation, ownerID(8), ownerID(7), references); err != nil {
		t.Fatal(err)
	}
	if v.OwnerStore.Pending != nil || !bytes.Equal(pending, make([]byte, len(pending))) || v.Secrets[selected].Name != "renamed" || v.Secrets[selected].Ref != ownerReferenceText(t, references[0]) || v.Secrets[other].Ref != ownerReferenceText(t, references[1]) {
		t.Fatal("verified metadata finalization lost names, versions or input cleanup")
	}
}

func TestOwnerStorePreparedRoundtripAndNewAlias(t *testing.T) {
	v, server := ownerStoreFixture(t)
	operation, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "token", ServerID: server, MediaType: "text/plain", Value: []byte("synthetic")})
	if err != nil {
		t.Fatal(err)
	}
	alias := v.OwnerStore.Pending.Change.AliasID
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), map[string]string{ownerID(2): ownerID(5)}); err != nil {
		t.Fatal(err)
	}
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	reference := ownerReference(t, 2, 5, 7)
	if err := decoded.FinishOwnerChange(operation, ownerID(8), ownerID(7), []appstoreref.Ref{reference}); err != nil {
		t.Fatal(err)
	}
	if decoded.Secrets[alias] != (SecretBinding{Name: "token", ServerID: server, Ref: ownerReferenceText(t, reference)}) {
		t.Fatal("reopened prepared intent did not restore its exact named binding")
	}
}

func TestVerifiedNoCommitRecoveryPreservesTheDraftValue(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	operation, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "token", MediaType: "text/plain", Value: []byte("retained pending value")})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), map[string]string{ownerID(2): ownerID(5)}); err != nil {
		t.Fatal(err)
	}
	if err := v.ReopenOwnerDraft(operation, ownerID(99), ownerID(7)); err == nil || v.OwnerStore.Pending.Phase != "prepared" {
		t.Fatal("uncorrelated recovery changed the prepared intent")
	}
	if err := v.ReopenOwnerDraft(operation, ownerID(8), ownerID(7)); err != nil {
		t.Fatal(err)
	}
	if v.OwnerStore.Pending.Phase != "draft" || v.OwnerStore.Pending.TransactionID != "" || !bytes.Equal(v.OwnerStore.Pending.Change.Value, []byte("retained pending value")) || len(v.Secrets) != 0 {
		t.Fatal("no-commit recovery lost private input or fabricated a committed alias")
	}
}

func TestOwnerStoreRemovalFinalizesWithoutAnotherObject(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	old := ownerReferenceText(t, ownerReference(t, 2, 3, 4))
	alias, err := v.BindSecret("", SecretBinding{Name: "token", Ref: old})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := v.StageOwnerChange(OwnerChange{Action: "remove", AliasID: alias, Name: "token", PreviousReference: old})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if err := v.FinishOwnerChange(operation, ownerID(8), ownerID(7), nil); err != nil || len(v.Secrets) != 0 || v.OwnerStore.Pending != nil {
		t.Fatal("owner removal did not finish the exact prepared alias change")
	}
}

func TestOwnerStoreRejectsUnknownOrMissingWireFields(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	if _, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "token", MediaType: "text/plain", Value: []byte("synthetic")}); err != nil {
		t.Fatal(err)
	}
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	for _, mutate := range []func(map[string]any){
		func(owner map[string]any) { owner["approved"] = true },
		func(owner map[string]any) { owner["master"] = nil },
		func(owner map[string]any) { owner["pending"].(map[string]any)["approved"] = true },
		func(owner map[string]any) { owner["pending"].(map[string]any)["phase"] = "received" },
		func(owner map[string]any) {
			owner["pending"].(map[string]any)["change"].(map[string]any)["extra"] = true
		},
		func(owner map[string]any) {
			delete(owner["pending"].(map[string]any)["change"].(map[string]any), "value")
		},
	} {
		value, err := pure.LoadsStrict(string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		root := value.(map[string]any)
		mutate(root["owner_store"].(map[string]any))
		text, err := pure.EmitCanonical(root)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := unmarshal([]byte(text))
		if err == nil {
			decoded.Close()
			t.Fatal("owner-store schema accepted an unknown or missing field")
		}
	}
}
