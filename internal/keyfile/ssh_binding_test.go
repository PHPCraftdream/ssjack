package keyfile

import "testing"

func TestSSHPasswordBindingUsesPrivateDomainAndRetainedMaster(t *testing.T) {
	calls := 0
	derive := func(password, salt []byte) []byte { calls++; return testDerive(password, salt) }
	u, err := newUnlocked([]byte("synthetic vault password"), 2, derive)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	identity, password := []byte("selected SSH identity"), []byte("synthetic SSH password")
	first, err := u.SSHPasswordBinding(identity, password)
	if err != nil || calls != 4 {
		t.Fatal("credential binding repeated derivation or failed")
	}
	for _, pair := range [][2][]byte{{identity, []byte("changed")}, {[]byte("other identity"), password}} {
		changed, err := u.SSHPasswordBinding(pair[0], pair[1])
		if err != nil || changed == first {
			t.Fatal("credential binding ignored identity or password changes")
		}
	}
	a, err := u.SSHPasswordBinding([]byte("a"), []byte("bc"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := u.SSHPasswordBinding([]byte("ab"), []byte("c"))
	if err != nil || a == b {
		t.Fatal("credential binding fields were not length-delimited")
	}
	encoded, err := u.Seal([]byte("synthetic encrypted payload"))
	if err != nil || calls != 4 {
		t.Fatal("binding changed the unlocked encryption lifecycle")
	}
	payload, reopened, err := unlock(encoded, []byte("synthetic vault password"), derive)
	if err != nil {
		t.Fatal(err)
	}
	clear(payload)
	defer reopened.Close()
	second, err := reopened.SSHPasswordBinding(identity, password)
	if err != nil || second != first || calls != 8 {
		t.Fatal("credential binding changed across a normal encrypted save")
	}
	other, err := newUnlocked([]byte("synthetic vault password"), 2, derive)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	different, err := other.SSHPasswordBinding(identity, password)
	if err != nil || different == first {
		t.Fatal("independent vault masters shared a password verifier")
	}
	u.Close()
	if _, err := u.SSHPasswordBinding(identity, password); err == nil {
		t.Fatal("closed unlock context produced a password binding")
	}
}

func TestSSHProxyBindingIsPrivateDomainSeparatedAndStable(t *testing.T) {
	calls := 0
	u, err := newUnlocked([]byte("synthetic vault password"), 2, func(password, salt []byte) []byte { calls++; return testDerive(password, salt) })
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	identity, private := []byte("selected routed SSH identity"), []byte("framed synthetic credentials")
	first, err := u.SSHProxyBinding(identity, private)
	if err != nil || calls != 4 {
		t.Fatal("proxy binding repeated the KDF")
	}
	legacy, err := u.SSHPasswordBinding(identity, private)
	if err != nil || first == legacy {
		t.Fatal("proxy and direct-password domains collided")
	}
	for _, pair := range [][2][]byte{{[]byte("changed route"), private}, {identity, []byte("changed private credentials")}} {
		changed, err := u.SSHProxyBinding(pair[0], pair[1])
		if err != nil || changed == first {
			t.Fatal("proxy binding ignored metadata or credentials")
		}
	}
	encoded, err := u.Seal([]byte("synthetic retained-key payload"))
	if err != nil {
		t.Fatal(err)
	}
	payload, reopened, err := unlock(encoded, []byte("synthetic vault password"), testDerive)
	clear(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.SSHProxyBinding(identity, private)
	if err != nil || again != first || calls != 4 {
		t.Fatal("proxy binding changed after encrypted reopen")
	}
	for _, pair := range [][2][]byte{{nil, private}, {identity, nil}, {make([]byte, MaxPlaintext+1), private}, {identity, make([]byte, 8193)}} {
		if _, err := u.SSHProxyBinding(pair[0], pair[1]); err == nil {
			t.Fatal("proxy binding accepted an invalid bound")
		}
	}
	u.Close()
	if _, err := u.SSHProxyBinding(identity, private); err == nil {
		t.Fatal("closed context produced a proxy binding")
	}
	var missing *Unlocked
	if _, err := missing.SSHProxyBinding(identity, private); err == nil {
		t.Fatal("missing owner context produced a proxy binding")
	}
}

func TestSSHPasswordBindingBounds(t *testing.T) {
	u, err := newUnlocked([]byte("synthetic"), 2, testDerive)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for _, pair := range [][2][]byte{{nil, []byte("p")}, {[]byte("i"), nil}, {make([]byte, MaxPlaintext+1), []byte("p")}, {[]byte("i"), make([]byte, 4097)}} {
		if _, err := u.SSHPasswordBinding(pair[0], pair[1]); err == nil {
			t.Fatal("invalid credential binding input was accepted")
		}
	}
	var closed *Unlocked
	if _, err := closed.SSHPasswordBinding([]byte("identity"), []byte("password")); err == nil {
		t.Fatal("missing unlock context produced a credential binding")
	}
}
