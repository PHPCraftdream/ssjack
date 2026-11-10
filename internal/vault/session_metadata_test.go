package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshlive"
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

func TestSessionAgentSSHBindingRejectsEachAuthorityMutation(t *testing.T) {
	for _, field := range []struct {
		name string
		edit func(*agentSourceFixture)
	}{
		{"profile", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			delete(f.session.state.Targets, f.profile)
			f.session.state.Targets["renamed-profile"] = target
			for id, server := range f.session.state.Servers {
				server.Accounts["main"] = "renamed-profile"
				f.session.state.Servers[id] = server
			}
			f.profile = "renamed-profile"
			f.materialProfile = "renamed-profile"
		}},
		{"server-id", func(f *agentSourceFixture) {
			for id, server := range f.session.state.Servers {
				delete(f.session.state.Servers, id)
				replacementID := id[:31] + "1"
				if replacementID == id {
					replacementID = id[:31] + "2"
				}
				f.session.state.Servers[replacementID] = server
				return
			}
		}},
		{"account", func(f *agentSourceFixture) {
			for id, server := range f.session.state.Servers {
				delete(server.Accounts, "main")
				server.Accounts["renamed-account"] = f.profile
				f.session.state.Servers[id] = server
			}
		}},
		{"address", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.Address = "changed.example:2222"
			f.session.state.Targets[f.profile] = target
		}},
		{"user", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.User = "changed-user"
			f.session.state.Targets[f.profile] = target
		}},
		{"authentication", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.Password = []byte("synthetic-password")
			target.PrivateKey = nil
			f.session.state.Targets[f.profile] = target
		}},
		{"usage", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.Usage = "agent"
			f.session.state.Targets[f.profile] = target
		}},
		{"host-pins", func(f *agentSourceFixture) {
			target, other := f.session.state.Targets[f.profile], testTarget(t)
			target.HostKeys = append([]string(nil), other.HostKeys...)
			clear(other.PrivateKey)
			f.session.state.Targets[f.profile] = target
		}},
		{"policy-hostkeys", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.SSHPolicy.HostKeys = []string{ssh.SupportedAlgorithms().HostKeys[0]}
			f.session.state.Targets[f.profile] = target
		}},
		{"policy-kex", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.SSHPolicy.KeyExchanges = []string{ssh.SupportedAlgorithms().KeyExchanges[0]}
			f.session.state.Targets[f.profile] = target
		}},
		{"policy-ciphers", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.SSHPolicy.Ciphers = []string{ssh.SupportedAlgorithms().Ciphers[0]}
			f.session.state.Targets[f.profile] = target
		}},
		{"policy-macs", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.SSHPolicy.MACs = []string{ssh.SupportedAlgorithms().MACs[0]}
			f.session.state.Targets[f.profile] = target
		}},
	} {
		t.Run(field.name, func(t *testing.T) {
			fixture := newAgentSourceFixture(t)
			baseline, err := fixture.source(context.Background())
			if err != nil {
				t.Fatal("healthy baseline source was unavailable")
			}
			runtime, err := sshlive.New(context.Background(), baseline.Profile, fixture.source)
			if err != nil {
				t.Fatal("baseline runtime was unavailable")
			}
			field.edit(&fixture)
			fixture.confirmHealthyChange()
			if err := fixture.session.state.validate(); err != nil {
				t.Fatal("isolated state mutation was invalid")
			}
			changed, err := fixture.source(context.Background())
			if err != nil {
				t.Fatal("healthy changed source was unavailable")
			}
			if changed.Scope == baseline.Scope {
				t.Fatal("authority mutation did not change the production scope")
			}
			admitted, err := runtime.Admit(context.Background(), baseline.Profile, "synthetic-command")
			status := runtime.Status()
			if !errors.Is(err, sshlive.ErrUnavailable) || admitted.Runner != nil || admitted.Guard != nil || admitted.Issued != nil || status.DeliveredKnown || status.AdoptedKnown || !status.Unavailable {
				t.Fatal("changed authority was admitted or marked delivered/adopted")
			}
		})
	}
}

func TestSessionAgentSSHBindingAllowsCredentialRotationAndDisplayRename(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*agentSourceFixture)
		edit  func(*agentSourceFixture)
	}{
		{"key-rotation", nil, func(f *agentSourceFixture) {
			target, replacement := f.session.state.Targets[f.profile], testTarget(t)
			target.PrivateKey = append([]byte(nil), replacement.PrivateKey...)
			clear(replacement.PrivateKey)
			f.session.state.Targets[f.profile] = target
		}},
		{"password-rotation", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.Password, target.PrivateKey = []byte("synthetic-password"), nil
			f.session.state.Targets[f.profile] = target
		}, func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.Password = []byte("rotated-password")
			f.session.state.Targets[f.profile] = target
		}},
		{"display-name", nil, func(f *agentSourceFixture) {
			for id, server := range f.session.state.Servers {
				server.Name = "renamed-display"
				f.session.state.Servers[id] = server
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentSourceFixture(t)
			if test.setup != nil {
				test.setup(&fixture)
				fixture.confirmHealthyChange()
				if err := fixture.session.state.validate(); err != nil {
					t.Fatal("valid credential setup rejected")
				}
			}
			baseline, err := fixture.source(context.Background())
			if err != nil {
				t.Fatal("healthy baseline source was unavailable")
			}
			runtime, err := sshlive.New(context.Background(), baseline.Profile, fixture.source)
			if err != nil {
				t.Fatal("baseline runtime was unavailable")
			}
			test.edit(&fixture)
			fixture.confirmHealthyChange()
			if err := fixture.session.state.validate(); err != nil {
				t.Fatal("valid positive-control mutation rejected")
			}
			changed, err := fixture.source(context.Background())
			if err != nil || changed.Scope != baseline.Scope {
				t.Fatal("allowed change altered the production scope")
			}
			admitted, err := runtime.Admit(context.Background(), baseline.Profile, "synthetic-command")
			status := runtime.Status()
			if err != nil || admitted.Runner == nil || admitted.Guard == nil || admitted.Issued == nil || !status.DesiredKnown || status.DesiredRevision != fixture.revision || status.DeliveredKnown || status.AdoptedKnown {
				t.Fatal("valid scope change was not admitted exactly before issuance")
			}
			admitted.Issued()
			status = runtime.Status()
			if !status.DeliveredKnown || status.DeliveredRevision != fixture.revision || status.AdoptedKnown {
				t.Fatal("issuance did not mark delivery without claiming adoption")
			}
		})
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
