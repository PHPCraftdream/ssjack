package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSessionMetadataOwnsCollectionsAndOmitsPrivateMaterial(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	alias, err := v.BindSecret("", SecretBinding{Name: "existing", Ref: directoryRef(t, 3)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "pending", MediaType: "text/plain", Value: []byte("synthetic pending private value")}); err != nil {
		t.Fatal(err)
	}
	var saves atomic.Int32
	s := newSession(v, func(context.Context, []byte) error { saves.Add(1); return nil }, func() {})
	defer s.Discard()
	metadata, err := s.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Servers) != 1 || len(metadata.Servers[0].Accounts) != 1 || metadata.Servers[0].Accounts[0].Authentication != "key" || metadata.Secrets[alias].Name != "existing" || metadata.OwnerStore == nil || metadata.OwnerStore.PendingPhase != "draft" {
		t.Fatal("display metadata omitted the expected safe context")
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range [][]byte{v.Targets["production"].PrivateKey, v.OwnerStore.Master, v.OwnerStore.Pending.Change.Value} {
		if bytes.Contains(encoded, private) || bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(private))) {
			t.Fatal("display metadata exposed private material")
		}
	}
	metadata.Servers[0].Name = "caller-mutated"
	metadata.Servers[0].Accounts[0].User = "caller-mutated"
	metadata.Servers[0].Fingerprints[0] = "caller-mutated"
	metadata.Secrets[alias] = SecretBinding{}
	metadata.OwnerStore.PendingPhase = "caller-mutated"
	again, err := s.Metadata()
	if err != nil || again.Servers[0].Name != "production" || again.Servers[0].Accounts[0].User == "caller-mutated" || again.Servers[0].Fingerprints[0] == "caller-mutated" || again.Secrets[alias].Name != "existing" || again.OwnerStore.PendingPhase != "draft" || saves.Load() != 0 {
		t.Fatal("read-only metadata mutated the database, leaked collections, or queued persistence")
	}
}

func TestSessionHumanSSHReturnsPinnedConfigForHumanAccountsOnly(t *testing.T) {
	v, server := directoryFixture(t)
	base := v.Targets["production"]
	pin, err := ParseHostKey([]byte(base.HostKeys[0]))
	if err != nil {
		t.Fatal(err)
	}
	other, err := ParseHostKey([]byte(testTarget(t).HostKeys[0]))
	if err != nil {
		t.Fatal(err)
	}
	password := Target{Address: base.Address, User: "password-user", Password: []byte("synthetic-password"), HostKeys: base.HostKeys}
	agent := Target{Address: base.Address, User: "agent-user", PrivateKey: base.PrivateKey, HostKeys: base.HostKeys, Usage: "agent"}
	if err := v.SetAccount(server, "password", password); err != nil {
		t.Fatal(err)
	}
	if err := v.SetAccount(server, "agent", agent); err != nil {
		t.Fatal(err)
	}
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	configs := make(map[string]*ssh.ClientConfig)
	for account, user := range map[string]string{"main": "test", "password": "password-user"} {
		config, address, err := s.HumanSSH(server, account)
		if err != nil || address != base.Address || config.User != user || len(config.Auth) != 1 {
			t.Fatal("human account did not yield its verified SSH configuration")
		}
		if config.HostKeyCallback("example.test:22", nil, pin) != nil || config.HostKeyCallback("example.test:22", nil, other) == nil {
			t.Fatal("configuration did not enforce the pinned host key")
		}
		configs[account] = config
	}
	for _, refused := range [][2]string{{server, "agent"}, {server, "missing"}, {"missing", "main"}} {
		if config, address, err := s.HumanSSH(refused[0], refused[1]); err == nil || config != nil || address != "" {
			t.Fatal("unavailable or agent-only account produced a human SSH configuration")
		}
	}
	err = s.Apply(func(c *Vault) error {
		return c.SetAccount(server, "password", Target{Address: base.Address, User: "changed", Password: []byte("changed-password"), HostKeys: base.HostKeys, Usage: "agent"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.HumanSSH(server, "password"); err == nil {
		t.Fatal("edited usage policy was not enforced")
	}
	s.Discard()
	if configs["password"].User != "password-user" || configs["password"].HostKeyCallback("example.test:22", nil, pin) != nil {
		t.Fatal("returned configuration depended on session-owned state")
	}
	if config, _, err := s.HumanSSH(server, "main"); err == nil || config != nil {
		t.Fatal("closed session produced an SSH configuration")
	}
}
