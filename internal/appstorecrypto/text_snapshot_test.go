package appstorecrypto

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func TestSyntheticCurrentTextSelectionHydratesPlaceholder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h, _, fault := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	path, artifact := nativeConsumerFixture(t)
	master, err := derive(ctx, h, []byte("synthetic text delivery"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()

	payload := make([]byte, 20000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	source, err := os.CreateTemp(t.TempDir(), "synthetic-text-input-")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Write(payload[17:]); err != nil {
		t.Fatal(err)
	}
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, []SnapshotObject{{ObjectID: [16]byte{1}, MediaType: "bin", Source: source}})
	if err != nil {
		t.Fatal(err)
	}
	ref := commit.Refs[0]
	token, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	selected := append(append([]byte{}, payload[:17]...), token...)
	before := append([]byte(nil), selected...)
	consumer := boundNativeConsumer(t, path, artifact, ref, commit.EncodedHash)
	result, err := master.deliverCurrentText(ctx, directory, fault.reader, ref, consumer, &textSelection{input: selected})
	if err != nil || !result.Complete || !result.MayHaveDelivered || result.Bytes != uint64(len(payload)) {
		t.Fatalf("hydrated synthetic text selection: %+v %v", result, err)
	}
	if !bytes.Equal(selected, before) {
		t.Fatal("text selection input was modified")
	}

	wrongVersion := ref.VersionID()
	wrongVersion[0] ^= 1
	if wrongVersion == ([16]byte{}) {
		wrongVersion[1] = 1
	}
	wrong, err := appstoreref.New(ref.StoreID(), ref.ObjectID(), wrongVersion, ref.SnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	wrongConsumer := boundNativeConsumer(t, path, artifact, wrong, commit.EncodedHash)
	denied, err := master.deliverCurrentText(ctx, directory, fault.reader, wrong, wrongConsumer, &textSelection{input: selected})
	if !errors.Is(err, appstoreref.ErrNotFound) || denied.MayHaveDelivered || denied.Complete {
		t.Fatalf("wrong version released: %+v %v", denied, err)
	}
}
