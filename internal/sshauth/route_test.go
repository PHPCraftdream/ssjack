package sshauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

func TestProxyRouteOwnsCredentialSnapshotAndKeepsFreshEvidence(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []ssh.AuthMethod{PublicKey(signer), Password([]byte("synthetic SSH password"))} {
		route := &sshproxy.Config{Type: sshproxy.SOCKS5, Address: "proxy.invalid:1080", Username: "operator", Password: []byte("synthetic proxy password")}
		method, err := WithProxy(base, route)
		if err != nil {
			t.Fatal(err)
		}
		route.Clear()
		route.Address = "changed.invalid:1080"
		config := &ssh.ClientConfig{Auth: []ssh.AuthMethod{method}}
		_, owned, err := connectionMethod(config)
		if err != nil || owned.Address != "proxy.invalid:1080" || string(owned.Password) != "synthetic proxy password" {
			t.Fatal("selected route borrowed vault-owned material")
		}
		first, used1, err := ForConnection(config)
		if err != nil {
			t.Fatal(err)
		}
		second, used2, err := ForConnection(config)
		if err != nil || first == second || first == config || used1() || used2() {
			t.Fatal("routed authentication reused evidence or mutable config")
		}
		if _, err := WithProxy(method, owned); err == nil {
			t.Fatal("nested proxy route accepted")
		}
		owned.Clear()
	}
}

func TestProxyMarkersCannotAuthorizeForeignOrMixedAuthentication(t *testing.T) {
	valid := &sshproxy.Config{Type: sshproxy.HTTP, Address: "proxy.invalid:8080"}
	for _, methods := range [][]ssh.AuthMethod{
		{&routedAuth{AuthMethod: ssh.Password("untracked"), proxy: valid}},
		{&routedAuth{AuthMethod: Password([]byte("selected"))}},
		{&routedAuth{AuthMethod: Password([]byte("selected")), proxy: &sshproxy.Config{Type: "unknown"}}},
		{&routedAuth{AuthMethod: Password([]byte("selected")), proxy: valid}, Password([]byte("fallback"))},
		{(*routedAuth)(nil)},
	} {
		if _, _, err := ForConnection(&ssh.ClientConfig{Auth: methods}); err == nil {
			t.Fatal("routed marker bypassed selected authentication validation")
		}
	}
	if _, err := WithProxy(ssh.Password("untracked"), valid); err == nil {
		t.Fatal("proxy wrapper accepted arbitrary SSH authentication")
	}
}
