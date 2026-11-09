//go:build linux && amd64

package appstorecrypto

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

type streamStepReader struct {
	input io.Reader
	calls int
}

func (r *streamStepReader) Read(p []byte) (int, error) {
	r.calls++
	if len(p) > 1 {
		p = p[:1]
	}
	return r.input.Read(p)
}

func TestPrivateStreamTemplateBindingOwnsContentAndOperation(t *testing.T) {
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	placeholder, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte("synthetic \xe2\x82\xac\n"), placeholder...)
	binding, err := newTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(binding.key[:])
	base := strings.Repeat("a", 64)
	first, count, err := streamTemplateBinding(context.Background(), &binding, base, bytes.NewReader(input), []appstoreref.Ref{ref})
	if err != nil || count != uint64(len(input)) {
		t.Fatal("private preparation binding failed")
	}
	chunked, _, err := streamTemplateBinding(context.Background(), &binding, base, &streamStepReader{input: bytes.NewReader(input)}, []appstoreref.Ref{ref})
	if err != nil || first != chunked {
		t.Fatal("read boundaries changed a private operation MAC")
	}
	changed, _, err := streamTemplateBinding(context.Background(), &binding, base, bytes.NewReader(append(input, '!')), []appstoreref.Ref{ref})
	if err != nil || changed == first {
		t.Fatal("changed second-pass content retained its private binding")
	}
	changed, _, err = streamTemplateBinding(context.Background(), &binding, strings.Repeat("b", 64), bytes.NewReader(input), []appstoreref.Ref{ref})
	if err != nil || changed == first {
		t.Fatal("another operation retained the template binding")
	}
}

func TestStreamPreparationRefusesBeforeReadingWithoutAuthority(t *testing.T) {
	input := &streamStepReader{input: strings.NewReader("unread template")}
	adapter := &TextStreamAdapter{adapter: &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: "hydrate-stream-v2", File: "/approved/config"}}}
	result, err := adapter.Prepare(context.Background(), "AAECAwQFBgcICQoLDA0ODw", "/approved/config", input)
	if err == nil || result.Ticket != "" || input.calls != 0 || adapter.prepared != nil || adapter.adapter.used {
		t.Fatal("unauthenticated preparation read input or created usable state")
	}
	ticket := &textStreamTicket{mac: [32]byte{1}}
	adapter.prepared = ticket
	if err := adapter.Close(); err != nil || adapter.prepared != nil || ticket.mac != ([32]byte{}) {
		t.Fatal("stream close retained private ticket state")
	}
}
