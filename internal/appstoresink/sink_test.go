package appstoresink

import (
	"context"
	_ "embed"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

//go:embed testdata/consumer/main.go
var fixedConsumerSource string

func TestFixedConsumerBindingAndUnsupported(t *testing.T) {
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Reference: ref, EncodedHash: [32]byte{1}, ArtifactHash: [32]byte{2}, Target: [32]byte{3}, Revision: [32]byte{4}, Purpose: [32]byte{5}, ExpiresAt: time.Now().Add(time.Hour)}
	if !validBinding(binding) {
		t.Fatal("valid binding refused")
	}
	base := bindingDigest(binding)
	for _, change := range []func(*Binding){
		func(b *Binding) { b.EncodedHash[0] ^= 1 },
		func(b *Binding) { b.ArtifactHash[0] ^= 1 },
		func(b *Binding) { b.Target[0] ^= 1 },
		func(b *Binding) { b.Revision[0] ^= 1 },
		func(b *Binding) { b.Purpose[0] ^= 1 },
		func(b *Binding) { b.ExpiresAt = b.ExpiresAt.Add(time.Nanosecond) },
	} {
		changed := binding
		change(&changed)
		if bindingDigest(changed) == base {
			t.Fatal("binding omitted a field")
		}
	}
	if validBinding(Binding{}) {
		t.Fatal("zero binding accepted")
	}
	_, err = New(Config{})
	if runtime.GOOS == "linux" {
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("empty Linux config: %v", err)
		}
		return
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported platform: %v", err)
	}
	if _, err := (&Consumer{}).Begin(context.Background(), ref, [32]byte{1}, 1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported delivery: %v", err)
	}
}
