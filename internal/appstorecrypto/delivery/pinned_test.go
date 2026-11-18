package delivery

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/anchorfixture"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoresink"
)

var (
	writerFixture          = anchorfixture.WriterFixture
	writerFixtureWithFault = anchorfixture.WriterFixtureWithFault
)

func fake(password, salt []byte) []byte { return anchorfixture.FakeKDF(password, salt) }

func derive(ctx context.Context, h appstoreheader.Header, passphrase []byte, fn masterkey.KDF) (*masterkey.Master, error) {
	return masterkey.DeriveHeld(ctx, h, passphrase, fn)
}

func nativeConsumerFixture(t *testing.T) (string, [32]byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exact-reference-consumer")
	command := exec.Command("go", "build", "-o", path, "../../appstoresink/testdata/consumer")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic consumer: %v\n%s", err, output)
	}
	program, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, sha256.Sum256(program)
}
func boundNativeConsumer(t *testing.T, path string, artifact [32]byte, reference appstoreref.Ref, encoded [32]byte) *appstoresink.Consumer {
	t.Helper()
	program, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := appstoresink.New(appstoresink.Config{Program: program, Binding: appstoresink.Binding{Reference: reference, EncodedHash: encoded, ArtifactHash: artifact, Target: [32]byte{3}, Revision: [32]byte{4}, Purpose: [32]byte{5}, ExpiresAt: time.Now().Add(time.Hour)}})
	_ = program.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = consumer.Close() })
	return consumer
}
func TestPrivateCurrentReferenceToFixedNativeConsumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h, _, fault := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	path, artifact := nativeConsumerFixture(t)
	master, err := derive(ctx, h, []byte("synthetic current delivery"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	objects := make([]snapshotstore.SnapshotObject, 2)
	for index, length := range []int{17, appstoreheader.ChunkSize + 19} {
		source, err := os.CreateTemp(t.TempDir(), "synthetic-input-")
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		payload := make([]byte, length)
		for offset := range payload {
			if index == 0 {
				payload[offset] = 0x99
			} else {
				payload[offset] = byte(offset % 251)
			}
		}
		if _, err = source.Write(payload); err != nil {
			t.Fatal(err)
		}
		clear(payload)
		objects[index] = snapshotstore.SnapshotObject{ObjectID: [16]byte{byte(index + 1)}, MediaType: "bin", Source: source}
	}
	writer, err := snapshotstore.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}
	if len(commit.Refs) != 2 {
		t.Fatal("missing exact references")
	}
	selected := commit.Refs[1]
	consumer := boundNativeConsumer(t, path, artifact, selected, commit.EncodedHash)
	placeholder, err := appstoreplaceholder.Encode(selected)
	if err != nil {
		t.Fatal(err)
	}
	requested, err := appstoreplaceholder.Parse(placeholder)
	if err != nil || requested != selected {
		t.Fatalf("placeholder identity: %v", err)
	}
	otherPlaceholder, err := appstoreplaceholder.Encode(commit.Refs[0])
	if err != nil {
		t.Fatal(err)
	}
	otherRequest, err := appstoreplaceholder.Parse(otherPlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := deliverCurrent(master, ctx, directory, fault.Reader, otherRequest, consumer)
	if !errors.Is(err, appstoresink.ErrDenied) || denied.MayHaveDelivered || denied.Complete {
		t.Fatalf("placeholder escaped fixed binding: %+v %v", denied, err)
	}
	result, err := deliverCurrent(master, ctx, directory, fault.Reader, requested, consumer)
	if err != nil || !result.Complete || !result.MayHaveDelivered || result.Bytes != appstoreheader.ChunkSize+19 {
		t.Fatalf("exact native receipt: %+v %v", result, err)
	}
	wrongVersion := selected.VersionID()
	wrongVersion[0] ^= 1
	if wrongVersion == ([16]byte{}) {
		wrongVersion[1] = 1
	}
	wrong, err := appstoreref.New(selected.StoreID(), selected.ObjectID(), wrongVersion, selected.SnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	wrongConsumer := boundNativeConsumer(t, path, artifact, wrong, commit.EncodedHash)
	result, err = deliverCurrent(master, ctx, directory, fault.Reader, wrong, wrongConsumer)
	if !errors.Is(err, appstoreref.ErrNotFound) || result.MayHaveDelivered || result.Complete {
		t.Fatalf("wrong version released: %+v %v", result, err)
	}
	if _, err := writer.Write(ctx, nil); err != nil {
		t.Fatal(err)
	}
	historical := boundNativeConsumer(t, path, artifact, selected, commit.EncodedHash)
	result, err = deliverCurrent(master, ctx, directory, fault.Reader, selected, historical)
	if err == nil || result.MayHaveDelivered || result.Complete {
		t.Fatalf("historical reference substituted current: %+v %v", result, err)
	}
}

func TestSecondPassTagFailureStopsBeforeAffectedChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	path, artifact := nativeConsumerFixture(t)
	master, err := derive(ctx, h, []byte("synthetic partial handoff"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	source, err := os.CreateTemp(t.TempDir(), "synthetic-partial-")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	payload := make([]byte, appstoreheader.ChunkSize+19)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := source.Write(payload); err != nil {
		t.Fatal(err)
	}
	clear(payload)
	writer, err := snapshotstore.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, []snapshotstore.SnapshotObject{{ObjectID: [16]byte{1}, MediaType: "bin", Source: source}})
	if err != nil {
		t.Fatal(err)
	}
	release, err := appstorebudget.TryAcquire(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	pinned, err := PinSnapshot(master, ctx, tx, masterkey.ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash})
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	entry, err := appstoreref.FindMetadata(commit.Refs[0], pinned.state.checked.Catalog())
	if err != nil {
		t.Fatal(err)
	}
	consumer := boundNativeConsumer(t, path, artifact, commit.Refs[0], commit.EncodedHash)
	session, err := consumer.Begin(ctx, commit.Refs[0], commit.EncodedHash, entry.Length())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := pinned.Recheck(ctx); err != nil {
		t.Fatal(err)
	}
	// Simulate a change after preflight, independently of the immutable-spool assumption.
	offset := int64(appstoreheader.Size + 2*(12+appstoreheader.ChunkSize+16000) + 12)
	var corrupt [1]byte
	if _, err := pinned.state.file.ReadAt(corrupt[:], offset); err != nil {
		t.Fatal(err)
	}
	corrupt[0] ^= 1
	if _, err := pinned.state.file.WriteAt(corrupt[:], offset); err != nil {
		t.Fatal(err)
	}
	result, err := streamPinnedObject(master, ctx, pinned, entry, session)
	if !errors.Is(err, masterkey.ErrAuthentication) || result.Complete || !result.MayHaveDelivered || result.Bytes != appstoreheader.ChunkSize {
		t.Fatalf("partial chunk boundary: %+v %v", result, err)
	}
}

func TestPinnedSnapshotPrivateCiphertextAndSharedClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic pinned snapshot"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	writer, err := snapshotstore.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	release, err := appstorebudget.TryAcquire(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	expected := masterkey.ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash}
	pinned, err := PinSnapshot(master, ctx, tx, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	if !pinned.state.checked.Valid() {
		t.Fatal("missing complete verification")
	}
	if _, err := appstorefile.StatTemporary(pinned.state.file); err != nil {
		t.Fatal(err)
	}
	if _, err := appstorefile.Stat(pinned.state.file); !errors.Is(err, appstorefile.ErrInvalid) {
		t.Fatalf("spool must be anonymous: %v", err)
	}
	original, err := tx.OpenSnapshot(expected.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	mutable, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", original.Fd()), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mutable.WriteAt([]byte{0x7f}, 0); err != nil {
		t.Fatal(err)
	}
	if err = mutable.Close(); err != nil {
		t.Fatal(err)
	}
	if err = pinned.Recheck(ctx); err != nil {
		t.Fatalf("source mutation affected private spool: %v", err)
	}
	if other, err := PinSnapshot(master, ctx, tx, expected); err == nil {
		_ = other.Close()
		t.Fatal("changed source was accepted")
	}
	alias := *pinned
	if err = pinned.Close(); err != nil {
		t.Fatal(err)
	}
	if err = alias.Recheck(ctx); !errors.Is(err, masterkey.ErrClosed) {
		t.Fatalf("copied handle after close: %v", err)
	}
	if err = alias.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedSnapshotHashCheckBeyondRevision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic pinned hash"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	writer, err := snapshotstore.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	release, err := appstorebudget.TryAcquire(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	expected := masterkey.ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash}
	pinned, err := PinSnapshot(master, ctx, tx, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	if _, err = pinned.state.file.WriteAt([]byte{0x7f}, 0); err != nil {
		t.Fatal(err)
	}
	// Remove the revision mismatch so this assertion independently requires the full hash.
	pinned.state.revision, err = appstorefile.StatTemporary(pinned.state.file)
	if err != nil {
		t.Fatal(err)
	}
	if err = pinned.Recheck(ctx); !errors.Is(err, masterkey.ErrSnapshot) {
		t.Fatalf("changed spool hash accepted: %v", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err = pinned.Recheck(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled recheck: %v", err)
	}
}
