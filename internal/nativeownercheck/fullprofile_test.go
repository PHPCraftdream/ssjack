package nativeownercheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/application/discovery"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrpc"
	"github.com/PHPCraftdream/ssjack/internal/ownerservice"
	"github.com/PHPCraftdream/ssjack/internal/vault"
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
	t.Run("owner-rpc", func(t *testing.T) { verifyOwnerRPC(t, ctx) })
	t.Run("import-plan", func(t *testing.T) { verifyImportPlanAdmission(t, ctx) })
	must(t, owner.Close())
	must(t, directory.Close())
	must(t, installation.Close())
	must(t, store.Close())
	t.Run("guard-linked", func(t *testing.T) { verifyLinkedGuardAdmission(t, ctx, path, binding.Header.StoreID(), password) })
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

func TestNativeOwnerApprovalProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF acceptance runs in native GitHub CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	root := t.TempDir()
	path := filepath.Join(root, "approval-vault.ktav")
	password := []byte("synthetic native approval profile password")
	defer clear(password)
	appDir := filepath.Join(root, "application")
	must(t, os.Mkdir(appDir, 0700))
	descriptor := filepath.Join(appDir, "ssjack-app.json")
	writeDescriptor := func(executable string) {
		t.Helper()
		data := []byte(`{"format":"ssjack-app-v1","name":"approval-app","launch":{"executable":"` + executable + `"}}`)
		must(t, os.WriteFile(descriptor, data, 0600))
	}
	writeDescriptor("/not-run")
	scan := discovery.Scan(root)
	if len(scan.Candidates) != 1 {
		t.Fatalf("fixture discovery candidates=%d", len(scan.Candidates))
	}
	candidate := scan.Candidates[0]
	canonical := candidate.CanonicalPath
	firstHash := hex.EncodeToString(candidate.Fingerprint[:])
	v := vault.NewDirectory()
	must(t, vault.CreateWithRecords(ctx, path, v, password))
	v.Close()
	manager, err := ownerdb.Open(ctx, path, password)
	must(t, err)
	defer manager.Discard()
	service, err := ownerservice.Start(ctx, manager, ownerservice.DefaultVerifier())
	must(t, err)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if err := service.Close(cleanup); err != nil {
			t.Error("owner service did not stop safely")
		}
	}()
	binding, err := manager.OwnerBinding()
	must(t, err)
	connection, err := ownerlocal.Dial(ctx, path)
	must(t, err)
	defer connection.Close()
	packet, err := manager.LocalOwnerPeer(binding)
	must(t, err)
	client, err := ownerrpc.Attach(ctx, connection, packet)
	must(t, err)
	defer client.Close()

	snapshot, err := client.Execute(ctx, ownerpacket.Command{Operation: "snapshot"})
	must(t, err)
	if snapshot.Status.Database.Pending || snapshot.Status.Database.Err != nil {
		t.Fatal("authenticated ready snapshot was not durable")
	}
	approvalFiles := func() []string {
		t.Helper()
		entries, err := os.ReadDir(filepath.Dir(path))
		must(t, err)
		prefix, suffix := filepath.Base(path)+".approval-snapshot-", ".ssjack.ktav"
		var files []string
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), suffix) {
				files = append(files, entry.Name())
			}
		}
		return files
	}
	preApprovalDigest := snapshot.CipherDigest
	if preApprovalDigest == ([32]byte{}) {
		t.Fatal("pre-approval snapshot has no ciphertext digest")
	}
	revision := snapshot.Status.Database.Revision
	change := ownerpacket.ApprovalChange{ApplicationName: candidate.Name, ApplicationPath: canonical, ReviewedHash: firstHash}
	snapshot, err = client.Execute(ctx, ownerpacket.Command{Operation: "approve_application", Revision: &revision, Approval: &change})
	must(t, err)
	if snapshot.Status.Database.Revision <= revision {
		t.Fatal("approval did not advance database revision")
	}
	if snapshot.Status.Database.SavedRevision != snapshot.Status.Database.Revision {
		t.Fatal("approval saved revision does not match new revision")
	}
	if snapshot.CipherDigest == preApprovalDigest {
		t.Fatal("approval did not change ciphertext digest")
	}
	if len(snapshot.Directory.Approvals) != 1 {
		t.Fatal("approval was not visible in owner RPC snapshot")
	}
	approval := snapshot.Directory.Approvals[0]
	if approval.Name != candidate.Name || approval.Path != canonical || approval.Hash != firstHash || approval.Route != "" {
		t.Fatalf("approval metadata mismatch: %+v", approval)
	}
	if snapshot.Status.Database.SavedRevision != snapshot.Status.Database.Revision || snapshot.Status.Pending || snapshot.Status.Err != nil || snapshot.Status.Database.Pending || snapshot.Status.Database.Err != nil || snapshot.Status.Busy {
		t.Fatal("approval reply did not report durable state")
	}
	firstSnapshots := approvalFiles()
	if len(firstSnapshots) != 1 {
		t.Fatalf("first approval produced %d encrypted evidence snapshots", len(firstSnapshots))
	}
	firstSnapshotBytes, err := os.ReadFile(filepath.Join(filepath.Dir(path), firstSnapshots[0]))
	must(t, err)
	if sha256.Sum256(firstSnapshotBytes) != preApprovalDigest {
		t.Fatal("approval snapshot bytes differ from pre-approval vault ciphertext")
	}

	writeDescriptor("/not-run-changed")
	changed := discovery.Scan(root)
	if len(changed.Candidates) != 1 {
		t.Fatalf("changed fixture discovery candidates=%d", len(changed.Candidates))
	}
	secondHash := hex.EncodeToString(changed.Candidates[0].Fingerprint[:])
	if secondHash == firstHash {
		t.Fatal("changed descriptor retained the reviewed fingerprint")
	}
	unchangedState := func(baselineRevision uint64, baselineDigest [32]byte) {
		t.Helper()
		current, err := client.Execute(ctx, ownerpacket.Command{Operation: "snapshot"})
		must(t, err)
		if current.Status.Database.Revision != baselineRevision {
			t.Fatal("refused approval changed database revision")
		}
		if current.CipherDigest != baselineDigest {
			t.Fatal("refused approval changed ciphertext digest")
		}
		if len(current.Directory.Approvals) != 1 {
			t.Fatal("refused approval changed RPC approval state")
		}
		got := current.Directory.Approvals[0]
		if got.Name != candidate.Name || got.Path != canonical || got.Hash != firstHash || got.Route != "" {
			t.Fatalf("refused approval changed RPC approval record: %+v", got)
		}
		snapshot = current
	}
	revision = snapshot.Status.Database.Revision
	baselineDigest := snapshot.CipherDigest
	changedChange := ownerpacket.ApprovalChange{ApplicationName: candidate.Name, ApplicationPath: canonical, ReviewedHash: secondHash}
	if _, err := client.Execute(ctx, ownerpacket.Command{Operation: "approve_application", Revision: &revision, Approval: &changedChange}); !errors.Is(err, ownerpacket.ErrReviewStale) {
		t.Fatalf("replacement without live replaces_hash: got %v, want typed review-stale", err)
	}
	unchangedState(revision, baselineDigest)
	changedChange.ReplacesHash = strings.Repeat("f", 64)
	revision = snapshot.Status.Database.Revision
	baselineDigest = snapshot.CipherDigest
	if _, err := client.Execute(ctx, ownerpacket.Command{Operation: "approve_application", Revision: &revision, Approval: &changedChange}); !errors.Is(err, ownerpacket.ErrReviewStale) {
		t.Fatalf("replacement with wrong replaces_hash: got %v, want typed review-stale", err)
	}
	unchangedState(revision, baselineDigest)
	changedChange.ReplacesHash = firstHash
	changedChange.ReviewedHash = firstHash
	revision = snapshot.Status.Database.Revision
	baselineDigest = snapshot.CipherDigest
	if _, err := client.Execute(ctx, ownerpacket.Command{Operation: "approve_application", Revision: &revision, Approval: &changedChange}); !errors.Is(err, ownerpacket.ErrReviewStale) {
		t.Fatalf("stale reviewed descriptor hash: got %v, want typed review-stale", err)
	}
	unchangedState(revision, baselineDigest)

	changedChange.ReviewedHash = secondHash
	revision = snapshot.Status.Database.Revision
	baselineDigest = snapshot.CipherDigest
	snapshot, err = client.Execute(ctx, ownerpacket.Command{Operation: "approve_application", Revision: &revision, Approval: &changedChange})
	must(t, err)
	if snapshot.Status.Database.Revision <= revision {
		t.Fatal("replacement approval did not advance database revision")
	}
	if snapshot.Status.Database.SavedRevision != snapshot.Status.Database.Revision {
		t.Fatal("replacement approval saved revision does not match new revision")
	}
	if snapshot.CipherDigest == baselineDigest {
		t.Fatal("replacement approval did not change ciphertext digest")
	}
	if len(snapshot.Directory.Approvals) != 1 || snapshot.Directory.Approvals[0].Name != candidate.Name || snapshot.Directory.Approvals[0].Path != canonical || snapshot.Directory.Approvals[0].Hash != secondHash || snapshot.Directory.Approvals[0].Route != "" {
		t.Fatal("replacement approval did not publish the changed descriptor hash through RPC")
	}
	revision = snapshot.Status.Database.Revision
	baselineDigest = snapshot.CipherDigest
	revoke := ownerpacket.ApprovalChange{ApplicationName: candidate.Name, ReviewedHash: secondHash, ReplacesHash: secondHash}
	snapshot, err = client.Execute(ctx, ownerpacket.Command{Operation: "revoke_application", Revision: &revision, Approval: &revoke})
	must(t, err)
	if snapshot.Status.Database.Revision <= revision {
		t.Fatal("revoke did not advance database revision")
	}
	if snapshot.Status.Database.SavedRevision != snapshot.Status.Database.Revision {
		t.Fatal("revoke saved revision does not match new revision")
	}
	if snapshot.CipherDigest == baselineDigest {
		t.Fatal("revoke did not change ciphertext digest")
	}
	pollCtx, cancelPoll := context.WithTimeout(ctx, 30*time.Second)
	defer cancelPoll()
	for {
		snapshot, err = client.Execute(pollCtx, ownerpacket.Command{Operation: "snapshot"})
		if pollCtx.Err() != nil {
			t.Fatal("revoke durability poll timed out")
		}
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Status.Database.SavedRevision == snapshot.Status.Database.Revision && !snapshot.Status.Pending && snapshot.Status.Err == nil && !snapshot.Status.Database.Pending && snapshot.Status.Database.Err == nil && !snapshot.Status.Busy {
			break
		}
		select {
		case <-pollCtx.Done():
			t.Fatal("revoke durability poll timed out")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if len(snapshot.Directory.Approvals) != 0 {
		t.Fatal("revoke left an approval record in owner RPC metadata")
	}
}
