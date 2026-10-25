package vault

import (
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEncryptedSSHPolicyRoundTripAndSafeApplication(t *testing.T) {
	safe := ssh.SupportedAlgorithms()
	v := New()
	defer v.Close()
	target := testTarget(t)
	v.Targets["main"] = target
	policy := SSHPolicy{HostKeys: safe.HostKeys[:1], KeyExchanges: safe.KeyExchanges[:1], Ciphers: safe.Ciphers[:1], MACs: safe.MACs[:1]}
	if err := v.ReplacePolicy("main", policy); err != nil {
		t.Fatal(err)
	}
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	got := decoded.Targets["main"]
	if !reflect.DeepEqual(got.SSHPolicy, policy) {
		t.Fatal("algorithm policy changed during encrypted-payload serialization")
	}
	config, err := got.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.Ciphers, policy.Ciphers) || !reflect.DeepEqual(config.HostKeyAlgorithms, policy.HostKeys) || config.HostKeyCallback == nil {
		t.Fatal("policy was ignored or disabled server trust")
	}
	defaultConfig, err := target.ClientConfig()
	if err != nil || !reflect.DeepEqual(defaultConfig.Ciphers, safe.Ciphers) {
		t.Fatal("default policy did not use supported safe algorithms")
	}
}

func TestUnsafeUnknownAndDuplicatePoliciesRejected(t *testing.T) {
	for _, policy := range []SSHPolicy{
		{Ciphers: []string{"none"}},
		{Ciphers: []string{"unknown-cipher"}},
		{MACs: []string{"not-a-supported-mac"}},
		{KeyExchanges: []string{"diffie-hellman-group1-sha1"}},
		{Ciphers: []string{ssh.SupportedAlgorithms().Ciphers[0], ssh.SupportedAlgorithms().Ciphers[0]}},
	} {
		if err := policy.Validate(); err == nil {
			t.Fatal("unsafe or duplicate policy was accepted")
		}
	}
}
