package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
)

func TestSyntheticCurrentTextReverseCopyToFixedNativeConsumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h, _, fault := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic reverse text delivery"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()

	secret := []byte("synthetic\n雪 secret")
	source, err := os.CreateTemp(t.TempDir(), "synthetic-reverse-input-")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Write(secret); err != nil {
		t.Fatal(err)
	}
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, []SnapshotObject{{ObjectID: [16]byte{1}, MediaType: "text/plain", Source: source}})
	if err != nil {
		t.Fatal(err)
	}
	ref := commit.Refs[0]
	token, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	selected := append([]byte("ordinary prefix "), secret...)
	selected = append(selected, []byte(" ordinary suffix")...)
	want := append([]byte("ordinary prefix "), token...)
	want = append(want, []byte(" ordinary suffix")...)
	digest := sha256.Sum256(want)

	path := filepath.Join(t.TempDir(), "reverse-fixed-consumer")
	argument := "-X main.expectedSHA256=" + hex.EncodeToString(digest[:])
	command := exec.Command("go", "build", "-ldflags", argument, "-o", path, "./testdata/textconsumer")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic reverse consumer: %v\n%s", err, output)
	}
	program, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	consumer := boundNativeConsumer(t, path, sha256.Sum256(program), ref, commit.EncodedHash)
	before := append([]byte(nil), selected...)
	result, err := master.deliverCurrentText(ctx, directory, fault.reader, ref, consumer, &textSelection{input: selected, reverse: true})
	if err != nil || !result.Complete || !result.MayHaveDelivered || result.Bytes != uint64(len(want)) {
		t.Fatalf("reverse-copied synthetic text selection: %+v %v", result, err)
	}
	if !bytes.Equal(selected, before) {
		t.Fatal("reverse copy modified source selection")
	}
}
