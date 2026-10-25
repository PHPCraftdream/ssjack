package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/ktav-lang/golang/pure"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

func testDerive(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 32, 1, 32)
}

func TestContainerRoundTripAndLayerGrowth(t *testing.T) {
	password := []byte("test secret")
	plaintext := []byte("private key bytes\x00\xff\n")
	calls := 0
	derive := func(password, salt []byte) []byte {
		calls++
		return testDerive(password, salt)
	}
	encoded, err := seal(plaintext, password, derive)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 4 || !IsContainer(encoded) {
		t.Fatalf("expected four KDF calls and container prefix, got %d", calls)
	}
	d, ciphertext, err := decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != len(plaintext)+1000*16 || d.Layers != 1000 || d.MemoryKiB != 1024*1024 {
		t.Fatal("incorrect layer growth or production parameters")
	}
	header, salts, nonce, err := d.header()
	if err != nil {
		t.Fatal(err)
	}
	master, err := masterKey(password, salts, testDerive)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	peeled := append([]byte(nil), ciphertext...)
	for index := 999; index >= 0; index-- {
		aead, layerNonce, aad, err := layer(master, nonce, header, "storage", index)
		if err != nil {
			t.Fatal(err)
		}
		peeled, err = aead.Open(peeled[:0], layerNonce, peeled, aad)
		if err != nil || len(peeled) != len(plaintext)+index*16 {
			t.Fatalf("layer %d: %v", index, err)
		}
	}
	if !bytes.Equal(peeled, plaintext) {
		t.Fatal("layers did not encrypt the original data")
	}
	opened, err := open(encoded, password, derive)
	if err != nil || !bytes.Equal(opened, plaintext) || calls != 8 {
		t.Fatalf("round trip failed: %v, KDF calls: %d", err, calls)
	}
	if !bytes.Equal(plaintext, []byte("private key bytes\x00\xff\n")) {
		t.Fatal("caller plaintext was mutated")
	}
	if _, err := open(encoded, []byte("wrong secret"), testDerive); err == nil {
		t.Fatal("wrong secret was accepted")
	}
}

func marshalDocument(t *testing.T, d document) []byte {
	t.Helper()
	body, err := pure.EmitCanonical(d)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(Magic + body)
}

func TestInvalidDocumentsRejectedBeforeKDF(t *testing.T) {
	encoded, err := seal([]byte("key"), []byte("secret"), testDerive)
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*document){
		"version":     func(d *document) { d.Version++ },
		"kdf":         func(d *document) { d.KDF = "other" },
		"memory":      func(d *document) { d.MemoryKiB++ },
		"passes":      func(d *document) { d.Passes++ },
		"parallelism": func(d *document) { d.Parallelism++ },
		"layers":      func(d *document) { d.Layers-- },
		"salts":       func(d *document) { d.Salts = d.Salts[:3] },
		"duplicate":   func(d *document) { d.Salts[1] = d.Salts[0] },
		"salt size":   func(d *document) { d.Salts[0] = "AA==" },
		"nonce":       func(d *document) { d.Nonce = "invalid" },
		"payload":     func(d *document) { d.Ciphertext = "invalid" },
		"short":       func(d *document) { d.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, Layers*tagSize)) },
	}
	neverDerive := func(_, _ []byte) []byte {
		t.Fatal("invalid header reached the KDF")
		return nil
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := d
			changed.Salts = append([]string(nil), d.Salts...)
			mutate(&changed)
			if _, err := open(marshalDocument(t, changed), []byte("secret"), neverDerive); err == nil {
				t.Fatal("invalid document was accepted")
			}
		})
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), encoded...), []byte("\nunknown: true\n")...),
		append(append([]byte(nil), encoded...), []byte("\nversion: 1\n")...),
		[]byte("not a container"),
		bytes.Repeat([]byte("x"), MaxSize+1),
	} {
		if _, err := open(bad, []byte("secret"), neverDerive); err == nil {
			t.Fatal("malformed document was accepted")
		}
	}
}

func TestCiphertextAndMetadataAuthentication(t *testing.T) {
	encoded, err := seal([]byte("key"), []byte("secret"), testDerive)
	if err != nil {
		t.Fatal(err)
	}
	d, ciphertext, err := decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, len(ciphertext) / 2, len(ciphertext) - 1} {
		changed := append([]byte(nil), ciphertext...)
		changed[offset] ^= 1
		bad, err := encode(d, changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := open(bad, []byte("secret"), testDerive); err == nil {
			t.Fatal("modified ciphertext was accepted")
		}
	}
	changed := d
	nonce, err := decodeFixed(d.Nonce, nonceSize)
	if err != nil {
		t.Fatal(err)
	}
	nonce[0] ^= 1
	changed.Nonce = base64.StdEncoding.EncodeToString(nonce)
	if _, err := open(marshalDocument(t, changed), []byte("secret"), testDerive); err == nil {
		t.Fatal("modified header was accepted")
	}
}

func TestFreshParametersAndLayerSeparation(t *testing.T) {
	first, err := newDocument()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newDocument()
	if err != nil {
		t.Fatal(err)
	}
	if first.Nonce == second.Nonce || first.Salts[0] == second.Salts[0] {
		t.Fatal("fresh containers reused random parameters")
	}
	header, salts, nonce, err := first.header()
	if err != nil {
		t.Fatal(err)
	}
	master, err := masterKey([]byte("secret"), salts, testDerive)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	nonces := make(map[string]bool)
	for index := range Layers {
		_, n, _, err := layer(master, nonce, header, "storage", index)
		if err != nil || nonces[string(n)] {
			t.Fatalf("nonce reuse at layer %d: %v", index, err)
		}
		nonces[string(n)] = true
	}
	storage, n, aad, err := layer(master, nonce, header, "storage", 0)
	if err != nil {
		t.Fatal(err)
	}
	sealed := storage.Seal(nil, n, []byte("data"), aad)
	for _, variant := range []struct {
		purpose string
		index   int
	}{{"storage", 1}, {"keygen", 0}} {
		other, n, aad, err := layer(master, nonce, header, variant.purpose, variant.index)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Open(nil, n, sealed, aad); err == nil {
			t.Fatal("layer or purpose separation failed")
		}
	}
}

func TestDerivedEd25519Key(t *testing.T) {
	password := []byte("handwritten test secret")
	calls := 0
	derive := func(password, salt []byte) []byte {
		calls++
		return testDerive(password, salt)
	}
	encoded, public, err := generate(password, derive)
	if err != nil || calls != 4 {
		t.Fatalf("generation: %v, KDF calls: %d", err, calls)
	}
	plaintext, err := open(encoded, password, testDerive)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	signer, err := ssh.ParsePrivateKey(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if signer.PublicKey().Type() != "ssh-ed25519" || !bytes.Equal(ssh.MarshalAuthorizedKey(signer.PublicKey()), public) {
		t.Fatal("public key does not match protected Ed25519 key")
	}
	d, _, err := decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	header, salts, nonce, err := d.header()
	if err != nil {
		t.Fatal(err)
	}
	master, err := masterKey(password, salts, testDerive)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	seed, err := deriveSeed(master, nonce, header)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	recovered, err := ssh.NewPublicKey(private.Public())
	if err != nil || !bytes.Equal(ssh.MarshalAuthorizedKey(recovered), public) {
		t.Fatal("same secret and public parameters did not reproduce key bytes")
	}
	_, otherPublic, err := generate(password, testDerive)
	if err != nil || bytes.Equal(public, otherPublic) {
		t.Fatal("new public salts did not change the generated key")
	}
}

func TestInputBounds(t *testing.T) {
	for _, plaintext := range [][]byte{nil, make([]byte, MaxPlaintext+1)} {
		if _, err := seal(plaintext, []byte("secret"), testDerive); err == nil {
			t.Fatal("invalid plaintext size was accepted")
		}
	}
	for _, password := range [][]byte{nil, make([]byte, 16*1024+1)} {
		if _, err := seal([]byte("key"), password, testDerive); err == nil {
			t.Fatal("invalid secret was accepted")
		}
	}
}
