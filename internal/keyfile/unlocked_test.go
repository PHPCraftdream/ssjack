package keyfile

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestUnlockedWritesReuseFourDerivationsWithFreshNonces(t *testing.T) {
	for _, version := range []int{1, 2} {
		calls := 0
		derive := func(password, salt []byte) []byte {
			calls++
			return testDerive(password, salt)
		}
		u, err := newUnlocked([]byte("secret"), version, derive)
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		first, err := u.Seal([]byte("first private payload"))
		if err != nil {
			t.Fatal(err)
		}
		second, err := u.Seal([]byte("second private payload"))
		if err != nil || calls != 4 {
			t.Fatalf("repeated writes derived again: %d %v", calls, err)
		}
		d1, c1, err := decode(first)
		if err != nil {
			t.Fatal(err)
		}
		d2, _, err := decode(second)
		if err != nil {
			t.Fatal(err)
		}
		if d1.Version != version || d2.Version != version || d1.Nonce == d2.Nonce || d1.Salts[0] != d2.Salts[0] {
			t.Fatal("cached master lost format/salts or reused a nonce")
		}
		header, _, nonce, err := d1.header()
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := decryptLayers(c1, u.master, nonce, header)
		if err != nil {
			t.Fatal(err)
		}
		if len(c1)-len(envelope) != 1000*16 {
			t.Fatal("cached write omitted data encryption layers")
		}
		clear(envelope)
		opened, reopened, err := unlock(second, []byte("secret"), derive)
		if err != nil || !bytes.Equal(opened, []byte("second private payload")) || calls != 8 {
			t.Fatalf("cached output cannot be reopened: %d %v", calls, err)
		}
		clear(opened)
		reopened.Close()
		owned := u.master
		u.Close()
		u.Close()
		if !bytes.Equal(owned, make([]byte, 32)) || u.master != nil {
			t.Fatal("Close did not clear the owned master")
		}
		if _, err := u.Seal([]byte("late write")); err == nil {
			t.Fatal("closed context encrypted data")
		}
	}
}

func TestUnlockedInputErrorsAndWrongPassword(t *testing.T) {
	u, err := newUnlocked([]byte("secret"), 2, testDerive)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for _, data := range [][]byte{nil, make([]byte, MaxPlaintext+1)} {
		if _, err := u.Seal(data); err == nil {
			t.Fatal("invalid cached write accepted")
		}
	}
	encoded, err := u.Seal([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, context, err := unlock(encoded, []byte("wrong"), testDerive); err == nil || context != nil {
		t.Fatal("wrong password produced an unlocked context")
	}
}

func TestUnlockedGenerationReusesHeavyMasterAndBindsIdentity(t *testing.T) {
	calls := 0
	derive := func(password, salt []byte) []byte { calls++; return testDerive(password, salt) }
	u, err := newUnlocked([]byte("typed vault secret"), 2, derive)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	public, private, err := u.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil || !bytes.Equal(ssh.MarshalAuthorizedKey(signer.PublicKey()), public) {
		t.Fatal("generated public/private identity differs")
	}
	if signer.PublicKey().Type() != "ssh-ed25519" || calls != 4 {
		t.Fatal("generation changed algorithm or repeated KDF")
	}
	other, otherPrivate, err := u.GenerateIdentity()
	clear(otherPrivate)
	if err != nil || bytes.Equal(public, other) {
		t.Fatal("fresh generation parameters reused an identity")
	}
	encoded, err := u.Seal(private)
	if err != nil || calls != 4 {
		t.Fatal("initial identity storage repeated KDF")
	}
	plaintext, err := open(encoded, []byte("typed vault secret"), testDerive)
	if err != nil || !bytes.Equal(plaintext, private) {
		t.Fatalf("encrypted identity round trip: %v", err)
	}
	clear(plaintext)
	u.Close()
	if _, _, err := u.GenerateIdentity(); err == nil {
		t.Fatal("closed context generated a private key")
	}
}
