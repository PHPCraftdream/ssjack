package nativeownercheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func header(t *testing.T) appstoreheader.Header {
	t.Helper()
	var raw [appstoreheader.Size]byte
	copy(raw[:8], "SSAPP001")
	binary.BigEndian.PutUint16(raw[8:10], 1)
	_, err := rand.Read(raw[12:44])
	must(t, err)
	binary.BigEndian.PutUint32(raw[60:64], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint64(raw[64:72], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint32(raw[72:76], 1)
	_, err = rand.Read(raw[80:])
	must(t, err)
	parsed, err := appstoreheader.Parse(raw[:])
	must(t, err)
	return parsed
}

func TestNativeOwnerFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF acceptance runs in native GitHub CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	path := filepath.Join(t.TempDir(), "store")
	root, err := ownerfs.MakeRoot(path)
	must(t, err)
	must(t, root.Close())
	store, err := appstoreentry.Open(path)
	must(t, err)
	defer store.Close()
	dev, ino, err := store.Identity()
	must(t, err)
	binding := authority(t, header(t), dev, ino)
	password := []byte("synthetic native production installation password")
	defer clear(password)
	encoded, err := appstorecrypto.NewInstallation(ctx, binding.Header, password, binding)
	must(t, err)
	defer clear(encoded)
	must(t, store.Install(encoded))
	loaded, digest, err := store.Load()
	must(t, err)
	defer clear(loaded)
	if !bytes.Equal(encoded, loaded) {
		t.Fatal("native binding changed encrypted bytes")
	}
	installation, err := appstorecrypto.UnlockInstallation(ctx, loaded, password)
	must(t, err)
	defer installation.Close()
	if !installation.DirectoryMatches(dev, ino) {
		t.Fatal("native installation lost directory binding")
	}
	file, err := store.Root()
	must(t, err)
	directory, err := appstorefile.Open(file, binding.Header.StoreID())
	must(t, file.Close())
	must(t, err)
	defer directory.Close()
	_, transport, err := installation.Writer(directory)
	must(t, err)
	create, err := appstoreanchorrequest.NewCreate(binding.Header.StoreID())
	must(t, err)
	reply, _, err := transport.Submit(ctx, create)
	must(t, err)
	must(t, transport.Close())
	if reply.Outcome() != appstoreanchorreply.Committed {
		t.Fatal("synthetic anchor genesis was not committed")
	}
	owner, err := appstorecrypto.NewOwnerEditor(ctx, installation, directory)
	must(t, err)
	defer owner.Close()
	value := []byte("synthetic first native owner secret value")
	object, err := owner.Add("text/plain", value)
	must(t, err)
	first, err := owner.Commit(ctx)
	must(t, err)
	if len(first.Refs) != 1 || first.State.Sequence() != 1 {
		t.Fatal("native first commit metadata changed")
	}
	verifySnapshot(t, ctx, installation, directory, first, value)
	verifyPinnedCopy(t, ctx, installation, directory, first)
	must(t, owner.Close())
	owner, err = appstorecrypto.NewOwnerEditor(ctx, installation, directory)
	must(t, err)
	defer owner.Close()
	metadata := owner.Objects()
	if len(metadata) != 1 || metadata[0].ObjectID != object || metadata[0].Reference != first.Refs[0] || metadata[0].Length != uint64(len(value)) || metadata[0].Pending {
		t.Fatal("native reopen lost authenticated owner metadata")
	}
	updated := []byte("synthetic updated native owner secret value")
	must(t, owner.Update(object, updated))
	second, err := owner.Commit(ctx)
	must(t, err)
	if len(second.Refs) != 1 || second.State.Sequence() != 2 || second.Refs[0] == first.Refs[0] || second.Refs[0].ObjectID() != object {
		t.Fatal("native update reused or lost immutable reference")
	}
	verifySnapshot(t, ctx, installation, directory, second, updated)
	must(t, owner.Close())
	owner, err = appstorecrypto.NewOwnerEditor(ctx, installation, directory)
	must(t, err)
	defer owner.Close()
	metadata = owner.Objects()
	if len(metadata) != 1 || metadata[0].Length != uint64(len(updated)) || metadata[0].Reference != second.Refs[0] {
		t.Fatal("native update did not survive owner reopen")
	}
	unchanged, err := owner.Commit(ctx)
	must(t, err)
	if unchanged.EncodedHash != second.EncodedHash || unchanged.State.Hash() != second.State.Hash() {
		t.Fatal("read-only owner commit changed native snapshot")
	}
	must(t, owner.Remove(object))
	third, err := owner.Commit(ctx)
	must(t, err)
	if len(third.Refs) != 0 || third.State.Sequence() != 3 {
		t.Fatal("native deletion commit changed")
	}
	must(t, owner.Close())
	owner, err = appstorecrypto.NewOwnerEditor(ctx, installation, directory)
	must(t, err)
	defer owner.Close()
	if len(owner.Objects()) != 0 {
		t.Fatal("native deletion was not persisted")
	}
	verifySnapshot(t, ctx, installation, directory, first, value)
	verifySnapshot(t, ctx, installation, directory, second, updated)
	must(t, store.VerifyUnchanged(digest))
}

func verifySnapshot(t *testing.T, ctx context.Context, installation *appstorecrypto.Installation, directory *appstorefile.Directory, commit appstorecrypto.SnapshotCommit, value []byte) {
	t.Helper()
	tx, err := directory.Lock()
	must(t, err)
	defer tx.Close()
	file, err := tx.OpenSnapshot(commit.State.CommittedSnapshotID())
	must(t, err)
	defer file.Close()
	expected := appstorecrypto.ExpectedSnapshot{StoreID: commit.State.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash}
	check, err := installation.CheckSnapshot(ctx, file, expected)
	must(t, err)
	if !check.Valid() || check.EncodedHash() != commit.EncodedHash {
		t.Fatal("native encrypted snapshot failed authenticated readback")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(io.LimitReader(file, int64(check.Header().EncodedSize())+1))
	must(t, err)
	if uint64(len(ciphertext)) != check.Header().EncodedSize() || bytes.Contains(ciphertext, value) {
		t.Fatal("native snapshot exposed plaintext or changed framing")
	}
}
