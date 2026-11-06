package appstorecrypto

import (
	"bytes"
	"context"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestOwnerExportSelectionRequiresExactCleanCurrentReferences(t *testing.T) {
	ctx, installation, directory := ownerFixture(t)
	owner := openOwnerFixture(t, ctx, installation, directory)
	object, err := owner.Add("text/plain", []byte("synthetic owner export value"))
	if err != nil {
		t.Fatal(err)
	}
	commit, err := owner.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ref := commit.Refs[0]
	binding := func(reference appstoreref.Ref) map[string]vault.SecretBinding {
		encoded, err := appstoreplaceholder.Encode(reference)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]vault.SecretBinding{"alias": {Name: "token", Ref: string(encoded)}}
	}
	owner.mu.Lock()
	selected, err := owner.exportReferences(binding(ref))
	owner.mu.Unlock()
	if err != nil || selected["alias"] != ref {
		t.Fatal("current exact export reference was refused")
	}
	version := ref.VersionID()
	version[0] ^= 128
	if version == ([16]byte{}) {
		version[1] = 1
	}
	changed, err := appstoreref.New(ref.StoreID(), ref.ObjectID(), version, ref.SnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	_, staleErr := owner.exportReferences(binding(changed))
	_, malformedErr := owner.exportReferences(map[string]vault.SecretBinding{"alias": {Name: "token", Ref: "not a reference"}})
	owner.mu.Unlock()
	if staleErr == nil || malformedErr == nil {
		t.Fatal("export silently used the latest value for another selected reference")
	}
	if err := owner.Update(object, []byte("uncommitted replacement")); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	_, dirtyErr := owner.exportReferences(binding(ref))
	owner.mu.Unlock()
	if dirtyErr == nil {
		t.Fatal("export included uncommitted owner RAM values")
	}
	if err := owner.AppendOwnerExport(ctx, &vault.OwnerExportPlan{}); err == nil {
		t.Fatal("export accepted an unauthenticated opaque plan")
	}
}

func TestOwnerGuardRequiresExactCleanBindingsAndOwnsCapturedValues(t *testing.T) {
	ctx, installation, directory := ownerFixture(t)
	owner := openOwnerFixture(t, ctx, installation, directory)
	stale := openOwnerFixture(t, ctx, installation, directory)
	object, err := owner.Add("text/plain", []byte("synthetic linked value"))
	if err != nil {
		t.Fatal(err)
	}
	commit, err := owner.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := appstoreplaceholder.Encode(commit.Refs[0])
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]vault.SecretBinding{"alias": {Name: "token", Ref: string(encoded)}}
	snapshot, err := owner.OutputGuard(ctx, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := owner.OutputGuard(ctx, nil); result == nil || err != nil {
		t.Fatal("clean empty binding set was refused")
	}
	if result, err := stale.OutputGuard(ctx, nil); result != nil || err != outputguard.ErrGuard {
		t.Fatal("stale editor granted an empty guard without history validation")
	}
	bad := map[string]vault.SecretBinding{"alias": {Name: "token", Ref: "not a reference"}}
	if result, err := owner.OutputGuard(ctx, bad); result != nil || err != outputguard.ErrGuard {
		t.Fatal("malformed binding granted a capability or exposed diagnostics")
	}
	ref := commit.Refs[0]
	version := ref.VersionID()
	version[0] ^= 128
	if version == ([16]byte{}) {
		version[1] = 1
	}
	changed, err := appstoreref.New(ref.StoreID(), ref.ObjectID(), version, ref.SnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	other, err := appstoreplaceholder.Encode(changed)
	if err != nil {
		t.Fatal(err)
	}
	bad["alias"] = vault.SecretBinding{Name: "token", Ref: string(other)}
	if result, err := owner.OutputGuard(ctx, bad); result != nil || err != outputguard.ErrGuard {
		t.Fatal("guard substituted current value for another immutable reference")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if result, err := owner.OutputGuard(cancelled, bindings); result != nil || err != outputguard.ErrGuard {
		t.Fatal("cancelled guard construction succeeded")
	}
	if err := owner.Update(object, []byte("uncommitted replacement")); err != nil {
		t.Fatal(err)
	}
	if result, err := owner.OutputGuard(ctx, bindings); result != nil || err != outputguard.ErrGuard {
		t.Fatal("dirty editor granted a capability")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := owner.OutputGuard(ctx, bindings); result != nil || err != outputguard.ErrGuard {
		t.Fatal("closed editor granted a capability")
	}
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("synthetic linked value|uncommitted replacement")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if result.String() != "[REDACTED]|uncommitted replacement" {
		t.Fatal("captured guard borrowed cleared values or adopted uncommitted state")
	}
}
