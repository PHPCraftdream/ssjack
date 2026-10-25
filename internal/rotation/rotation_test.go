package rotation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func rotationKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	block, err := ssh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), ssh.MarshalAuthorizedKey(public)
}

func TestRotationStopsAtEveryFailureAndOrdersVerification(t *testing.T) {
	oldPrivate, oldPublic := rotationKey(t)
	newPrivate, newPublic := rotationKey(t)
	defer clear(oldPrivate)
	defer clear(newPrivate)
	original := vault.Target{Address: "example.test:22", User: "test", PrivateKey: oldPrivate, HostKeys: []string{string(oldPublic)}, Usage: "human"}
	stages := []string{"preserve", "confirm", "add", "verify", "commit"}
	for failAt := -1; failAt < len(stages); failAt++ {
		var seen []string
		failure := errors.New("intentional stage failure")
		step := func(name string) error {
			seen = append(seen, name)
			if failAt >= 0 && name == stages[failAt] {
				return failure
			}
			return nil
		}
		err := Apply(context.Background(), original, newPrivate, newPublic, Operations{
			Preserve: func(context.Context) error { return step("preserve") },
			Confirm:  func() error { return step("confirm") },
			Add:      func(context.Context, vault.Target, []byte) error { return step("add") },
			Verify: func(_ context.Context, replacement vault.Target) error {
				if replacement.User != original.User || replacement.Usage != original.Usage || replacement.HostKeys[0] != original.HostKeys[0] {
					t.Fatal("rotation changed connection metadata or pins")
				}
				return step("verify")
			},
			Commit: func(context.Context, vault.Target) error { return step("commit") },
		})
		want := stages
		if failAt >= 0 {
			want = stages[:failAt+1]
			if !errors.Is(err, failure) {
				t.Fatalf("failure at %s lost its cause: %v", stages[failAt], err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(seen, want) {
			t.Fatalf("unsafe stage ordering: %v, want %v", seen, want)
		}
	}
}

func TestCancellationAfterRemoteAdditionDoesNotSwitchVault(t *testing.T) {
	oldPrivate, oldPublic := rotationKey(t)
	newPrivate, newPublic := rotationKey(t)
	defer clear(oldPrivate)
	defer clear(newPrivate)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	committed := false
	err := Apply(ctx, vault.Target{Address: "example.test:22", User: "test", PrivateKey: oldPrivate, HostKeys: []string{string(oldPublic)}}, newPrivate, newPublic, Operations{
		Preserve: func(context.Context) error { return nil }, Confirm: func() error { return nil },
		Add:    func(context.Context, vault.Target, []byte) error { cancel(); return nil },
		Verify: func(context.Context, vault.Target) error { t.Fatal("verification after cancellation"); return nil },
		Commit: func(context.Context, vault.Target) error { committed = true; return nil },
	})
	if !errors.Is(err, context.Canceled) || committed {
		t.Fatal("cancelled rotation switched the vault")
	}
}
