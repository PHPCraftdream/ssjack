package keyfile

import (
	"bytes"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKeyfileFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in GitHub CI")
	}
	password := []byte("production derived identity fixture secret")
	encoded, public, plaintext, err := GenerateRecovery(password)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	if version, err := Format(encoded); err != nil || version != 2 {
		t.Fatal("generation did not emit v2")
	}
	opened, err := Open(encoded, password)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("recovery round trip: %v", err)
	}
	defer clear(opened)
	signer, err := ssh.ParsePrivateKey(opened)
	if err != nil || !bytes.Equal(ssh.MarshalAuthorizedKey(signer.PublicKey()), public) {
		t.Fatal("recovery public/private binding failed")
	}
}
