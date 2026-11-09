package vault

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/ktav-lang/golang/pure"
)

func remoteFixture(t *testing.T) (*Vault, string, string) {
	t.Helper()
	v, ssh := directoryFixture(t)
	v.RemoteMCP = mcpdirectory.New()
	server, err := v.RemoteMCP.AddServer("docs", "https://docs.invalid/mcp")
	if err != nil {
		t.Fatal(err)
	}
	account, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: server, Name: "work", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-private-MCP-token")}})
	if err != nil {
		t.Fatal(err)
	}
	return v, ssh, account
}
func TestRemoteMCPRoundTripPreferencesAndOwnedMetadata(t *testing.T) {
	v, ssh, account := remoteFixture(t)
	binding, err := v.RemoteMCP.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RememberRemoteMCP(ssh, "main", []mcpdirectory.Binding{binding}); err != nil {
		t.Fatal(err)
	}
	target := ownTarget(v.Targets["production"])
	defer clear(target.PrivateKey)
	defer clear(target.Password)
	defer target.Proxy.Clear()
	if err := v.SetAccount(ssh, "admin", target); err != nil {
		t.Fatal(err)
	}
	if suggested, err := v.SuggestedRemoteMCP(ssh, "admin"); err != nil || len(suggested) != 0 {
		t.Fatal("MCP preference leaked into another SSH account")
	}
	if err := v.RenameServer(ssh, "renamed"); err != nil {
		t.Fatal(err)
	}
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if !reflect.DeepEqual(v.RemoteMCP, decoded.RemoteMCP) {
		t.Fatal("MCP directory changed during vault round trip")
	}
	if suggested, err := decoded.SuggestedRemoteMCP(ssh, "main"); err != nil || len(suggested) != 1 || suggested[0] != binding {
		t.Fatal("SSH rename or vault reopen lost confirmed MCP selection")
	}
	owned := decoded.RemoteMCP.Accounts[account].Auth.Secret
	session := newSession(decoded, func(context.Context, []byte) error { return nil }, func() {})
	metadata, err := session.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.RemoteMCP.Accounts) != 1 || !metadata.RemoteMCP.Accounts[0].CredentialSet {
		t.Fatal("MCP metadata lost credential presence")
	}
	metadata.RemoteMCP.Last["production"][0].AccountID = "changed"
	if decoded.RemoteMCP.Last["production"][0].AccountID != account {
		t.Fatal("MCP metadata borrowed selection buffers")
	}
	session.Discard()
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("vault close retained MCP credential bytes")
	}
}
func TestRemoteMCPOldPayloadAndUnknownFieldsRefuseLoss(t *testing.T) {
	old, _ := directoryFixture(t)
	encoded, err := marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(encoded)
	clear(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if decoded.RemoteMCP != nil {
		t.Fatal("old database gained MCP state implicitly")
	}
	v, _, _ := remoteFixture(t)
	encoded, err = marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	raw, err := pure.LoadsStrict(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	root := raw.(map[string]any)
	remote := root["remote_mcp"].(map[string]any)
	remote["unknown"] = true
	bad, err := pure.EmitCanonical(root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded, err := unmarshal([]byte(bad)); err == nil {
		loaded.Close()
		t.Fatal("unknown MCP field was silently discarded")
	}
	v.RemoteMCP.Last["missing-profile"] = []mcpdirectory.Binding{}
	if _, err := marshal(v); err == nil {
		t.Fatal("MCP preference accepted an unknown SSH context")
	}
}
func TestRemoteMCPVaultLimitRefusesAtomicallyAndClearsCandidate(t *testing.T) {
	v, _ := directoryFixture(t)
	session := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	defer session.Discard()
	var owned []byte
	err := session.Apply(func(candidate *Vault) error {
		candidate.RemoteMCP = mcpdirectory.New()
		server, err := candidate.RemoteMCP.AddServer("docs", "https://docs.invalid/mcp")
		if err != nil {
			return err
		}
		for _, name := range []string{"one", "two", "three", "four", "five", "six", "seven", "eight", "nine"} {
			secret := bytes.Repeat([]byte("s"), 8192)
			id, err := candidate.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: server, Name: name, Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: secret}})
			clear(secret)
			if err != nil {
				return err
			}
			owned = candidate.RemoteMCP.Accounts[id].Auth.Secret
		}
		return nil
	})
	if err == nil || session.Status().Revision != 0 {
		t.Fatal("oversized MCP payload changed the vault")
	}
	metadata, err := session.Metadata()
	if err != nil || len(metadata.RemoteMCP.Servers) != 0 {
		t.Fatal("failed MCP edit changed committed metadata")
	}
	if len(owned) == 0 || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("failed MCP candidate retained private credentials")
	}
}
