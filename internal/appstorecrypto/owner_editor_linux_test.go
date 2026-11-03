package appstorecrypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
)

func ownerFixture(t *testing.T) (context.Context, *Installation, *appstorefile.Directory) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	directory, _, binding := installationWriterFixture(t)
	password := []byte("synthetic owner fixture password")
	defer clear(password)
	encoded, err := newInstallation(ctx, binding.Header, password, binding, installationDerive)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := unlockInstallation(ctx, encoded, password, installationDerive)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = installation.Close() })
	return ctx, installation, directory
}

func openOwnerFixture(t *testing.T, ctx context.Context, installation *Installation, directory *appstorefile.Directory) *OwnerEditor {
	t.Helper()
	owner, err := NewOwnerEditor(ctx, installation, directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return owner
}

func TestOwnerEditorPreservesAllObjectsAcrossVersions(t *testing.T) {
	ctx, installation, directory := ownerFixture(t)
	owner := openOwnerFixture(t, ctx, installation, directory)
	if len(owner.Objects()) != 0 {
		t.Fatal("fresh owner store was not empty")
	}
	value := []byte("first synthetic value")
	firstID, err := owner.Add("text/plain", value)
	if err != nil {
		t.Fatal(err)
	}
	clear(value)
	if !bytes.Equal(owner.objects[firstID].value, []byte("first synthetic value")) {
		t.Fatal("owner editor borrowed the caller's value buffer")
	}
	first, err := owner.Commit(ctx)
	if err != nil || len(first.Refs) != 1 || first.State.Sequence() != 1 {
		t.Fatalf("first owner commit failed: %v", err)
	}
	oldBytes := owner.objects[firstID].value
	if err := owner.Update(firstID, []byte("updated synthetic value")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldBytes, make([]byte, len(oldBytes))) {
		t.Fatal("superseded owner value was not cleared")
	}
	secondID, err := owner.Add("text/plain", []byte("second synthetic value"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.Commit(ctx)
	if err != nil || len(second.Refs) != 2 || second.State.Sequence() != 2 {
		t.Fatalf("second owner commit failed: %v", err)
	}
	if first.Refs[0] == owner.objects[firstID].reference || first.Refs[0].ObjectID() != owner.objects[firstID].reference.ObjectID() {
		t.Fatal("value update lost its object identity or reused its immutable version")
	}
	owned := owner.objects[firstID].value
	if err := owner.Close(); err != nil || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("owner close did not clear owned values")
	}
	reopened := openOwnerFixture(t, ctx, installation, directory)
	if len(reopened.Objects()) != 2 || !bytes.Equal(reopened.objects[firstID].value, []byte("updated synthetic value")) || !bytes.Equal(reopened.objects[secondID].value, []byte("second synthetic value")) {
		t.Fatal("owner reopen lost current secret values")
	}
	noChange, err := reopened.Commit(ctx)
	if err != nil || noChange.State.Hash() != second.State.Hash() || noChange.EncodedHash != second.EncodedHash {
		t.Fatal("read-only owner inspection changed the store")
	}
	removed := reopened.objects[secondID].value
	if err := reopened.Remove(secondID); err != nil || !bytes.Equal(removed, make([]byte, len(removed))) {
		t.Fatal("owner deletion did not clear removed RAM values")
	}
	third, err := reopened.Commit(ctx)
	if err != nil || len(third.Refs) != 1 || third.State.Sequence() != 3 {
		t.Fatalf("owner deletion commit failed: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	final := openOwnerFixture(t, ctx, installation, directory)
	if len(final.Objects()) != 1 || !bytes.Equal(final.objects[firstID].value, []byte("updated synthetic value")) {
		t.Fatal("deleting one object changed another object's value")
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	historical, err := tx.OpenSnapshot(first.State.CommittedSnapshotID())
	if err != nil {
		t.Fatal("owner update removed the immutable historical snapshot")
	}
	historical.Close()
}

func TestOwnerEditorRejectsStaleSnapshotBeforeMutation(t *testing.T) {
	ctx, installation, directory := ownerFixture(t)
	first := openOwnerFixture(t, ctx, installation, directory)
	stale := openOwnerFixture(t, ctx, installation, directory)
	if _, err := first.Add("text/plain", []byte("first owner value")); err != nil {
		t.Fatal(err)
	}
	commit, err := first.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := stale.Add("text/plain", []byte("stale owner value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stale.Commit(ctx); !errors.Is(err, ErrOwnerChanged) {
		t.Fatal("stale owner overwrote unseen changes")
	}
	if _, err := stale.Commit(ctx); !errors.Is(err, ErrWriterPending) {
		t.Fatal("failed owner commit was automatically retried")
	}
	if err := stale.Update(id, []byte("retry")); err == nil {
		t.Fatal("blocked owner editor accepted an implicit retry edit")
	}
	state, err := writerRead(ctx, first.transport, directory.StoreID())
	if err != nil || state.Hash() != commit.State.Hash() {
		t.Fatal("stale owner attempt changed anchor state or burned a reservation")
	}
}

func TestOwnerEditorRefusesInvalidValuesWithoutMutation(t *testing.T) {
	var zero OwnerEditor
	if _, err := zero.Add("text/plain", []byte("invalid owner")); err == nil {
		t.Fatal("uninitialized owner editor accepted values")
	}
	if _, err := zero.Commit(context.Background()); err == nil {
		t.Fatal("uninitialized owner editor reported a commit")
	}
	ctx, installation, directory := ownerFixture(t)
	owner := openOwnerFixture(t, ctx, installation, directory)
	for _, input := range []struct {
		media string
		value []byte
	}{{"invalid", []byte("value")}, {"text/plain", make([]byte, maxRAMSecretSize+1)}} {
		if _, err := owner.Add(input.media, input.value); err == nil {
			t.Fatal("invalid owner object was accepted")
		}
	}
	if len(owner.Objects()) != 0 {
		t.Fatal("invalid owner input changed the object set")
	}
	if err := owner.Update([16]byte{1}, []byte("value")); err == nil {
		t.Fatal("missing object update was accepted")
	}
	if err := owner.Remove([16]byte{1}); err == nil {
		t.Fatal("missing object deletion was accepted")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Add("text/plain", []byte("closed")); err == nil {
		t.Fatal("closed owner editor accepted values")
	}
}
