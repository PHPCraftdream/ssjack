package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/kdfgate"
	"golang.org/x/crypto/argon2"
)

func header(t *testing.T) appstoreheader.Header {
	t.Helper()
	literal := "535341505030303100010000" + strings.Repeat("01", 16) + strings.Repeat("02", 16) + strings.Repeat("00", 16) +
		"0010000000000000001000000000000100000000" +
		strings.Repeat("11", 32) + strings.Repeat("22", 32) + strings.Repeat("33", 32) + strings.Repeat("44", 32) + strings.Repeat("55", 12)
	b, err := hex.DecodeString(literal)
	if err != nil {
		t.Fatal(err)
	}
	h, err := appstoreheader.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func fake(password, salt []byte) []byte {
	h := sha256.Sum256(append(append([]byte(nil), password...), salt...))
	return append([]byte(nil), h[:]...)
}

func hkdfOracle(ikm []byte, domain string) [32]byte {
	extract := hmac.New(sha256.New, make([]byte, 32))
	_, _ = extract.Write(ikm)
	prk := extract.Sum(nil)
	defer clear(prk)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte(domain))
	_, _ = expand.Write([]byte{1})
	var key [32]byte
	copy(key[:], expand.Sum(nil))
	return key
}

func TestMasterExactInputsDomainAndClearing(t *testing.T) {
	h := header(t)
	password := []byte(" two words é ")
	before := append([]byte(nil), password...)
	salts := h.Salts()
	combined := make([]byte, 0, 128)
	for _, salt := range salts {
		combined = append(combined, fake(password, salt[:])...)
	}
	want := hkdfOracle(combined, "ssjack-appstore/v1/master")
	ssh := hkdfOracle(combined, "ssjack-key/v1/master")
	clear(combined)
	calls := 0
	var ownedPassword []byte
	var parts [][]byte
	m, err := derive(context.Background(), h, password, func(p, salt []byte) []byte {
		if calls >= 4 || !bytes.Equal(p, before) || !bytes.Equal(salt, salts[calls][:]) {
			t.Fatal("independent derivation input/order changed")
		}
		if release, admitted := kdfgate.TryAcquire(); admitted {
			release()
			t.Error("app-store derive bypassed shared admission")
		}
		calls++
		ownedPassword = p
		part := fake(p, salt)
		parts = append(parts, part)
		return part
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if calls != 4 || m.state.key != want || m.state.key == ssh || m.Closed() || !m.Matches(h) {
		t.Fatal("master profile/domain/context changed")
	}
	if !bytes.Equal(password, before) || !bytes.Equal(ownedPassword, make([]byte, len(before))) {
		t.Fatal("caller changed or owned passphrase retained")
	}
	for _, part := range parts {
		if !bytes.Equal(part, make([]byte, 32)) {
			t.Fatal("derived part not cleared")
		}
	}
	release, admitted := kdfgate.TryAcquire()
	if !admitted {
		t.Fatal("derivation retained admission")
	}
	release()
}

func TestPassphraseAndContextAdmission(t *testing.T) {
	h := header(t)
	calls := 0
	fn := func(p, salt []byte) []byte { calls++; return fake(p, salt) }
	for _, p := range [][]byte{nil, {}, make([]byte, 16385), {'a', 0, 'b'}, {0xff}, {0xed, 0xa0, 0x80}} {
		m, err := derive(context.Background(), h, p, fn)
		if !errors.Is(err, ErrInvalid) || m != nil || calls != 0 {
			t.Fatal("invalid passphrase reached KDF")
		}
	}
	for _, row := range []struct {
		ctx    context.Context
		header appstoreheader.Header
		fn     deriveFunc
	}{
		{nil, h, fn}, {context.Background(), appstoreheader.Header{}, fn}, {context.Background(), h, nil},
	} {
		m, err := derive(row.ctx, row.header, []byte("synthetic"), row.fn)
		if !errors.Is(err, ErrInvalid) || m != nil || calls != 0 {
			t.Fatal("invalid context/header/function reached KDF")
		}
	}
	var keys [][32]byte
	for _, p := range []string{" two words ", "two words", "é", string([]rune{'e', 0x0301}), strings.Repeat("x", 16384), "exact\n"} {
		m, err := derive(context.Background(), h, []byte(p), fake)
		if err != nil {
			t.Fatal(err)
		}
		for _, old := range keys {
			if old == m.state.key {
				t.Fatal("whitespace/Unicode bytes were normalized")
			}
		}
		keys = append(keys, m.state.key)
		m.Close()
	}
}

func TestCancellationAndBadOutputPublishNoMaster(t *testing.T) {
	h := header(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	m, err := derive(ctx, h, []byte("synthetic"), func(p, salt []byte) []byte { calls++; return fake(p, salt) })
	if !errors.Is(err, context.Canceled) || m != nil || calls != 0 {
		t.Fatal("already cancelled context derived")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var part, owned []byte
	m, err = derive(ctx, h, []byte("synthetic"), func(p, salt []byte) []byte {
		calls++
		owned = p
		cancel()
		if release, ok := kdfgate.TryAcquire(); ok {
			release()
			t.Error("cancel released an active KDF")
		}
		part = fake(p, salt)
		return part
	})
	if !errors.Is(err, context.Canceled) || m != nil || calls != 1 || !bytes.Equal(part, make([]byte, 32)) || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("mid-round cancellation published or retained key material")
	}
	m, err = derive(context.Background(), h, []byte("synthetic"), func(p, salt []byte) []byte { owned = p; part = make([]byte, 31); part[0] = 1; return part })
	if !errors.Is(err, ErrDerivation) || m != nil || !bytes.Equal(part, make([]byte, 31)) || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("invalid output published or retained material")
	}
	release, ok := kdfgate.TryAcquire()
	if !ok {
		t.Fatal("failure leaked KDF admission")
	}
	release()
}

func TestOwnedMasterCopiesAndClose(t *testing.T) {
	h := header(t)
	m, err := derive(context.Background(), h, []byte("synthetic"), fake)
	if err != nil {
		t.Fatal(err)
	}
	alias := *m
	for _, offset := range []int{12, 80} {
		raw := h.Bytes()
		raw[offset] ^= 0x80
		other, err := appstoreheader.Parse(raw[:])
		if err != nil || m.Matches(other) {
			t.Fatal("foreign store/salts matched dedicated master")
		}
	}
	raw := h.Bytes()
	raw[28] ^= 0x80
	raw[208] ^= 1
	snapshot, err := appstoreheader.Parse(raw[:])
	if err != nil || !m.Matches(snapshot) {
		t.Fatal("fresh snapshot lost dedicated store/salt context")
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); alias.Close() }()
	}
	workers.Wait()
	if !m.Closed() || !alias.Closed() || m.Matches(h) || m.state.key != ([32]byte{}) {
		t.Fatal("copied handles did not share key clearing")
	}
	var zero Master
	var nilMaster *Master
	if !zero.Closed() || !nilMaster.Closed() || zero.Matches(h) || nilMaster.Matches(h) {
		t.Fatal("zero/nil master ready")
	}
	zero.Close()
	nilMaster.Close()
	m.Close()
}

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
