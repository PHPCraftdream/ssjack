package appstorecrypto

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/kdfgate"
	"golang.org/x/crypto/argon2"
)

func TestAppstoreMasterFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production app-store KDF runs only in GitHub CI")
	}
	ctx := context.Background()
	h := header(t)
	password := []byte("synthetic production app-store master fixture")
	defer clear(password)
	m, err := Derive(ctx, h, password)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Independent full-cost inputs and HMAC-based RFC5869 oracle.
	release, err := kdfgate.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var combined [128]byte
	defer clear(combined[:])
	salts := h.Salts()
	for i := range salts {
		part := argon2.IDKey(password, salts[i][:], 1, 1048576, 1, 32)
		copy(combined[i*32:(i+1)*32], part)
		clear(part)
		runtime.GC()
	}
	want := hkdfOracle(combined[:], "ssjack-appstore/v1/master")
	defer clear(want[:])
	if m.state.key != want || m.Closed() || !m.Matches(h) {
		t.Fatal("production app-store master differs from independent fixed-profile oracle")
	}
	m.Close()
	if !m.Closed() || m.state.key != ([32]byte{}) {
		t.Fatal("production owned master was not cleared")
	}
}
