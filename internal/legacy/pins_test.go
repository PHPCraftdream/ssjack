package legacy

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func hostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestPinsAreBoundToExactAddressWithoutDNS(t *testing.T) {
	wanted, other := hostKey(t), hostKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	data := knownhosts.Line([]string{"home.example:22"}, wanted) + "\n" + knownhosts.Line([]string{"other.example:22"}, other) + "\n# trailing comment\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	pins, err := HostPins(path, "home.example:22")
	if err != nil || len(pins) != 1 || pins[0] != string(ssh.MarshalAuthorizedKey(wanted)) {
		t.Fatalf("pin binding: %v %v", pins, err)
	}
	if _, err := HostPins(path, "missing.example:22"); err == nil {
		t.Fatal("another host's pin was imported")
	}
	if _, err := HostPins(path, "home.example:2222"); err == nil {
		t.Fatal("another port's pin was imported")
	}
}

func TestHashedAndRevokedPins(t *testing.T) {
	key := hostKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	hashed := knownhosts.HashHostname(knownhosts.Normalize("home.example:22"))
	line := hashed + " " + string(ssh.MarshalAuthorizedKey(key))
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if pins, err := HostPins(path, "home.example:22"); err != nil || len(pins) != 1 {
		t.Fatalf("hashed pin: %v", err)
	}
	if err := os.WriteFile(path, []byte(line+"@revoked "+knownhosts.Line([]string{"home.example:22"}, key)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := HostPins(path, "home.example:22"); err == nil {
		t.Fatal("revoked key was imported")
	}
}
