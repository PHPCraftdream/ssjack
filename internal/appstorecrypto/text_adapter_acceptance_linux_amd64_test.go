//go:build linux && amd64

package appstorecrypto

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
)

func TestTextAdapterEngineRunnerBoundary(t *testing.T) {
	reference, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	placeholder, err := appstoreplaceholder.Encode(reference)
	if err != nil {
		t.Fatal(err)
	}
	selection := append([]byte("ordinary prefix "), placeholder...)
	selection = append(selection, []byte(" ordinary suffix")...)
	secret := []byte("synthetic-secret")
	transformed, err := appstoretext.Replace(selection, []appstoretext.Mapping{{Reference: reference, Value: secret}}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(transformed)
	var received []byte
	runner := TextAdapterRunner(func(_ context.Context, profile, command string, input io.Reader, stdout, stderr io.Writer) (int, error) {
		if profile != "approved" || command != "approved-command" || stdout != io.Discard || stderr != io.Discard {
			t.Error("unexpected destination binding")
		}
		var readErr error
		received, readErr = io.ReadAll(input)
		_, _ = stdout.Write(secret)
		_, _ = stderr.Write(secret)
		return 0, readErr
	})
	outcome := deliverTextAdapterOutput(context.Background(), runner, "approved", "approved-command", transformed, func() error { return nil })
	if outcome.Status != DeliveryReceived {
		t.Fatalf("delivery outcome=%v", outcome.Status)
	}
	defer clear(received)
	if !bytes.Equal(received, []byte("ordinary prefix synthetic-secret ordinary suffix")) {
		t.Fatal("literal substitution or ordinary text preservation failed")
	}
}
