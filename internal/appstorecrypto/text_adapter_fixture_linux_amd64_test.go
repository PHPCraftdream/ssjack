//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TextAdapterFixture(t *testing.T) (*Installation, declarativeauthority.TextAdapterGrant, string) {
	installation, grant, refs := TextAdapterFixtureValues(t, [][]byte{[]byte("synthetic-connected-secret")})
	return installation, grant, refs[0]
}

// TextAdapterFixtureValues creates a test installation containing each value.
// Returned references follow commit order, which is the catalog's object-ID
// order; each object ID is the corresponding value's one-based index in byte 0.
func TextAdapterFixtureValues(t *testing.T, values [][]byte) (*Installation, declarativeauthority.TextAdapterGrant, []string) {
	t.Helper()
	if len(values) < 1 || len(values) > 16 {
		t.Fatal("expected between 1 and 16 values")
	}
	for _, value := range values {
		if len(value) == 0 || len(value) > 1<<20 {
			t.Fatal("each value must contain between 1 byte and 1 MiB")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	directory, store, binding := installationWriterFixture(t)
	password := []byte("synthetic installation writer fixture")
	defer clear(password)
	encoded, err := newInstallation(ctx, binding.Header, password, binding, installationDerive)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if err = store.Install(encoded); err != nil {
		t.Fatal(err)
	}
	loaded, digest, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(loaded)
	installation, err := unlockInstallation(ctx, loaded, password, installationDerive)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = installation.Close() })
	writer, transport, err := installation.Writer(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	objects := make([]SnapshotObject, 0, len(values))
	for i, value := range values {
		var objectID [16]byte
		objectID[0] = byte(i + 1)
		if len(value) > maxRAMSecretSize {
			// This private test fixture bypasses NewSecretObject's 16 KiB public
			// fixture limit to exercise the 1 MiB owner limit; production is unchanged.
			source := &ramSource{data: append([]byte(nil), value...)}
			object := SnapshotObject{ObjectID: objectID, MediaType: "text/plain", memory: source}
			objects = append(objects, object)
			t.Cleanup(source.Close)
			continue
		}
		object, release, createErr := NewSecretObject(objectID, "text/plain", value)
		if createErr != nil {
			t.Fatal(createErr)
		}
		objects = append(objects, object)
		t.Cleanup(release)
	}
	commit, err := writer.WriteFirst(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.VerifyUnchanged(digest); err != nil {
		t.Fatal(err)
	}
	if len(commit.Refs) != len(values) {
		t.Fatalf("expected %d exact references, got %d", len(values), len(commit.Refs))
	}
	placeholders := make([]string, len(commit.Refs))
	for _, ref := range commit.Refs {
		objectID := ref.ObjectID()
		index := int(objectID[0]) - 1
		if index < 0 || index >= len(placeholders) {
			t.Fatalf("unexpected object ID index %d", objectID[0])
		}
		placeholder, encodeErr := appstoreplaceholder.Encode(ref)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		placeholders[index] = string(placeholder)
	}
	dev, ino, err := store.Identity()
	if err != nil {
		t.Fatal(err)
	}
	root, err := store.Root()
	if err != nil {
		t.Fatal(err)
	}
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(root.Fd())))
	_ = root.Close()
	if err != nil {
		t.Fatal(err)
	}
	var grantID [16]byte
	if _, err = rand.Read(grantID[:]); err != nil {
		t.Fatal(err)
	}
	credential := sha256.Sum256([]byte("synthetic-approved-consumer"))
	grant := declarativeauthority.TextAdapterGrant{
		ID:                 base64.RawURLEncoding.EncodeToString(grantID[:]),
		RecipientUID:       os.Geteuid(),
		StorePath:          path,
		DirectoryDev:       dev,
		DirectoryIno:       ino,
		InstallationSHA256: hex.EncodeToString(digest[:]),
		EncodedHash:        hex.EncodeToString(commit.EncodedHash[:]),
		References:         placeholders,
		Profile:            "approved",
		CredentialSHA256:   hex.EncodeToString(credential[:]),
		Command:            "approved-consumer",
		File:               "/approved/config",
		Mode:               "hydrate-v1",
		ExpiresAt:          time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
	}
	return installation, grant, placeholders
}
