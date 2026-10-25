package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestOpenSSHImportExportPreservesIdentity(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "test")
	if err != nil {
		t.Fatal(err)
	}
	original := pem.EncodeToMemory(block)
	before := append([]byte(nil), original...)
	if encrypted, err := RequiresPassphrase(original); err != nil || encrypted {
		t.Fatalf("plaintext detection: %t %v", encrypted, err)
	}
	imported, err := ImportSSH(original, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(imported)
	public, err := PublicSSH(imported)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("export test passphrase")
	exported, err := ExportSSH(imported, password)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted, err := RequiresPassphrase(exported); err != nil || !encrypted {
		t.Fatalf("export is not encrypted: %t %v", encrypted, err)
	}
	_, err = ssh.ParseRawPrivateKey(exported)
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		t.Fatal("exported private key can be parsed without its passphrase")
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase(exported, password)
	if err != nil || !bytes.Equal(ssh.MarshalAuthorizedKey(signer.PublicKey()), public) {
		t.Fatal("OpenSSH export changed the key identity")
	}
	if _, err := ImportSSH(exported, []byte("wrong")); err == nil {
		t.Fatal("wrong import passphrase was accepted")
	}
	reimported, err := ImportSSH(exported, password)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(reimported)
	reimportedPublic, err := PublicSSH(reimported)
	if err != nil || !bytes.Equal(reimportedPublic, public) {
		t.Fatal("reimport changed key identity")
	}
	if !bytes.Equal(original, before) {
		t.Fatal("import/export changed caller input bytes")
	}
	if _, err := ExportSSH(imported, nil); err == nil {
		t.Fatal("unencrypted private-key export was accepted")
	}
}

func TestPEMImportFormatsAndTrailingData(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ed)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pkcs8)
	for _, block := range []*pem.Block{
		{Type: "PRIVATE KEY", Bytes: pkcs8},
		{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)},
	} {
		encoded := pem.EncodeToMemory(block)
		imported, err := ImportSSH(encoded, nil)
		if err != nil {
			t.Fatalf("PEM import %s: %v", block.Type, err)
		}
		if _, err := ssh.ParsePrivateKey(imported); err != nil {
			t.Fatal(err)
		}
		clear(imported)
		if _, err := ImportSSH(append(append([]byte(nil), encoded...), encoded...), nil); err == nil {
			t.Fatal("multiple input private keys were accepted")
		}
	}
	for _, invalid := range [][]byte{nil, []byte("not a key"), make([]byte, 1024*1024+1)} {
		if _, err := RequiresPassphrase(invalid); err == nil {
			t.Fatal("invalid source was accepted")
		}
	}
}
