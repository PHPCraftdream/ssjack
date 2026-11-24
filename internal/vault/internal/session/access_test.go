package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/approval"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/vaulttest"
)

func TestSessionMetadataOwnsCollectionsAndOmitsPrivateMaterial(t *testing.T) {
	v, _ := vaulttest.OwnerStoreFixture(t)
	alias, err := v.BindSecret("", SecretBinding{Name: "existing", Ref: vaulttest.DirectoryRef(t, 3)})
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

func TestSessionAgentSSHScopeChangesForEachAuthorityMutation(t *testing.T) {
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
			target, other := f.session.state.Targets[f.profile], vaulttest.Target(t)
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
			baseline, err := fixture.source()
			if err != nil {
				t.Fatal("healthy baseline source was unavailable")
			}
			field.edit(&fixture)
			fixture.confirmHealthyChange()
			if err := core.Validate(fixture.session.state); err != nil {
				t.Fatal("isolated state mutation was invalid")
			}
			changed, err := fixture.source()
			if err != nil {
				t.Fatal("healthy changed source was unavailable")
			}
			if changed.Scope == baseline.Scope || changed.Revision <= baseline.Revision || changed.Config == nil || changed.Address == "" || changed.Guard == nil {
				t.Fatal("authority mutation did not change the production scope and return confirmed material")
			}
		})
	}
}

func TestSessionAgentSSHScopeAllowsCredentialRotationAndDisplayRename(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*agentSourceFixture)
		edit  func(*agentSourceFixture)
	}{
		{"key-rotation", nil, func(f *agentSourceFixture) {
			target, replacement := f.session.state.Targets[f.profile], vaulttest.Target(t)
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
				if err := core.Validate(fixture.session.state); err != nil {
					t.Fatal("valid credential setup rejected")
				}
			}
			baseline, err := fixture.source()
			if err != nil {
				t.Fatal("healthy baseline source was unavailable")
			}
			test.edit(&fixture)
			fixture.confirmHealthyChange()
			if err := core.Validate(fixture.session.state); err != nil {
				t.Fatal("valid positive-control mutation rejected")
			}
			changed, err := fixture.source()
			if err != nil || changed.Scope != baseline.Scope || changed.Revision <= baseline.Revision || changed.Config == nil || changed.Address == "" || changed.Guard == nil {
				t.Fatal("allowed change altered the production scope or failed to return confirmed material")
			}
			if len(changed.Config.Auth) != 1 || changed.Config.User == "" {
				t.Fatal("credential replacement did not return a valid SSH configuration")
			}
		})
	}
}

func TestSessionHumanSSHReturnsPinnedConfigForHumanAccountsOnly(t *testing.T) {
	v, server := vaulttest.DirectoryFixture(t)
	base := v.Targets["production"]
	pin, err := record.ParseHostKey([]byte(base.HostKeys[0]))
	if err != nil {
		t.Fatal(err)
	}
	other, err := record.ParseHostKey([]byte(vaulttest.Target(t).HostKeys[0]))
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

func captureSession(t *testing.T) (*Session, string, mcpdirectory.Binding, mcpdirectory.Binding, mcpdirectory.Binding, [32]byte) {
	t.Helper()
	state, server := vaulttest.DirectoryFixture(t)
	profile, err := state.AccountProfile(server, "main")
	if err != nil {
		t.Fatal(err)
	}
	state.RemoteMCP = mcpdirectory.New()
	remoteA, err := state.RemoteMCP.AddServer("remote-a", "https://capture-a.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := state.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remoteA, Name: "keyed", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-capture-secret")}})
	if err != nil {
		t.Fatal(err)
	}
	bindingA, err := state.RemoteMCP.CurrentBinding(keyed)
	if err != nil {
		t.Fatal(err)
	}
	remoteB, err := state.RemoteMCP.AddServer("remote-b", "https://capture-b.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	open, err := state.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remoteB, Name: "open", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "none"}})
	if err != nil {
		t.Fatal(err)
	}
	bindingB, err := state.RemoteMCP.CurrentBinding(open)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := state.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remoteA, Name: "off", Enabled: false, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-disabled-secret")}})
	if err != nil {
		t.Fatal(err)
	}
	account := state.RemoteMCP.Accounts[closed]
	disabledBinding := mcpdirectory.Binding{ServerID: account.ServerID, AccountID: closed, ServerRevision: state.RemoteMCP.Servers[account.ServerID].Revision, AccountRevision: account.Revision}
	digest := [32]byte{5}
	session := newSession(state, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(session.Discard)
	session.mu.Lock()
	session.savedCipher = digest
	session.saveDigest = func() [32]byte { return digest }
	session.mu.Unlock()
	return session, profile, bindingA, bindingB, disabledBinding, digest
}

// captureGate snapshots the mutable session gate fields so a refusal test can
// restore them before the fixture cleanup discards the session, even when the
// subtest fails.
type captureGate struct {
	state      *Vault
	closed     bool
	closing    bool
	revision   uint64
	saved      uint64
	saveErr    error
	cipher     [32]byte
	ownerStore *OwnerStore
	remoteMCP  *mcpdirectory.Directory
}

func snapshotCaptureGate(s *Session) captureGate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return captureGate{
		state: s.state, closed: s.closed, closing: s.closing,
		revision: s.revision, saved: s.saved, saveErr: s.saveErr,
		cipher: s.savedCipher, ownerStore: s.state.OwnerStore, remoteMCP: s.state.RemoteMCP,
	}
}

func restoreCaptureGate(s *Session, gate captureGate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.closed, s.closing = gate.state, gate.closed, gate.closing
	s.revision, s.saved, s.saveErr, s.savedCipher = gate.revision, gate.saved, gate.saveErr, gate.cipher
	if gate.state != nil {
		gate.state.OwnerStore, gate.state.RemoteMCP = gate.ownerStore, gate.remoteMCP
	}
}

func TestRemoteMCPCaptureRequiresExactConfirmedState(t *testing.T) {
	digest := [32]byte{5}
	cases := []struct {
		name string
		edit func(*Session)
	}{
		{"closed", func(s *Session) { s.closed = true }},
		{"closing", func(s *Session) { s.closing = true }},
		{"missing-state", func(s *Session) { s.state = nil }},
		{"revision", func(s *Session) { s.revision++ }},
		{"unsaved", func(s *Session) { s.saved-- }},
		{"save-error", func(s *Session) { s.saveErr = errors.New("synthetic private diagnostic") }},
		{"digest", func(s *Session) { s.savedCipher[0]++ }},
		{"owner-pending", func(s *Session) { s.state.OwnerStore = &OwnerStore{Pending: &OwnerIntent{}} }},
		{"remote-mcp-missing", func(s *Session) { s.state.RemoteMCP = nil }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			s, profile, bindingA, _, _, _ := captureSession(t)
			gate := snapshotCaptureGate(s)
			t.Cleanup(func() { restoreCaptureGate(s, gate) })
			test.edit(s)
			ctx := vaulttest.Context(t)
			if capture, err := s.RemoteMCPCaptureAt(ctx, 0, digest, profile, []mcpdirectory.Binding{bindingA}); capture != nil || err != mcpgrant.ErrGrant {
				t.Fatal("unconfirmed state granted a capture or exposed diagnostics")
			}
		})
	}
	s, profile, bindingA, _, _, _ := captureSession(t)
	ctx := vaulttest.Context(t)
	cancelled, stop := context.WithCancel(ctx)
	stop()
	oversized := make([]mcpdirectory.Binding, mcpdirectory.MaxSelections+1)
	for i := range oversized {
		oversized[i] = bindingA
	}
	for _, test := range []struct {
		name     string
		ctx      context.Context
		digest   [32]byte
		profile  string
		bindings []mcpdirectory.Binding
	}{
		{"unknown-profile", ctx, digest, "missing", []mcpdirectory.Binding{bindingA}},
		{"nil-bindings", ctx, digest, profile, nil},
		{"empty-bindings", ctx, digest, profile, []mcpdirectory.Binding{}},
		{"oversized-bindings", ctx, digest, profile, oversized},
		{"zero-digest", ctx, [32]byte{}, profile, []mcpdirectory.Binding{bindingA}},
		{"cancelled-context", cancelled, digest, profile, []mcpdirectory.Binding{bindingA}},
		{"nil-context", nil, digest, profile, []mcpdirectory.Binding{bindingA}},
	} {
		if capture, err := s.RemoteMCPCaptureAt(test.ctx, 0, test.digest, test.profile, test.bindings); capture != nil || err != mcpgrant.ErrGrant {
			t.Fatal(test.name + " argument was accepted")
		}
	}
	if capture, err := (*Session)(nil).RemoteMCPCaptureAt(ctx, 0, digest, profile, []mcpdirectory.Binding{bindingA}); capture != nil || err != mcpgrant.ErrGrant {
		t.Fatal("nil session was accepted")
	}
}

func TestRemoteMCPCaptureOwnsRecordsIndependentOfVaultClose(t *testing.T) {
	s, profile, bindingA, bindingB, _, digest := captureSession(t)
	ctx := vaulttest.Context(t)
	capture, err := s.RemoteMCPCaptureAt(ctx, 0, digest, profile, []mcpdirectory.Binding{bindingA, bindingB})
	if err != nil {
		t.Fatal(err)
	}
	s.Discard()
	launch, err := capture.Issue(ctx, profile, 0, []mcpdirectory.Binding{bindingA, bindingB})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := launch.Guard()
	if err != nil || guard == nil {
		t.Fatal(err)
	}
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(guard, &result)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("synthetic-capture-secret|Bearer synthetic-capture-secret|public")
	for _, value := range input {
		if _, err := writer.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	segments := bytes.Split(result.Bytes(), []byte("|"))
	if string(segments[0]) != outputguard.Marker {
		t.Fatal("capture lost the credential after vault close")
	}
	if string(segments[1]) != outputguard.Marker {
		t.Fatal("capture lost the transmitted authentication literal")
	}
	if string(segments[2]) != "public" {
		t.Fatal("capture masked public output")
	}
	if err := launch.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := capture.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if launch, err = capture.Issue(ctx, profile, 0, []mcpdirectory.Binding{bindingA, bindingB}); launch != nil || err != mcpgrant.ErrGrant {
		t.Fatal("closed capture was reused")
	}
}

func TestRemoteMCPCaptureRefusesStaleDisabledDuplicateAndUnknownBindings(t *testing.T) {
	s, profile, bindingA, bindingB, disabled, digest := captureSession(t)
	ctx := vaulttest.Context(t)
	staleAccount := bindingA
	staleAccount.AccountRevision++
	staleServer := bindingA
	staleServer.ServerRevision++
	unknown := mcpdirectory.Binding{ServerID: bindingA.ServerID, AccountID: "unknown", ServerRevision: bindingA.ServerRevision, AccountRevision: bindingA.AccountRevision}
	swapped := bindingB
	swapped.ServerID = bindingA.ServerID
	for _, test := range []struct {
		name     string
		bindings []mcpdirectory.Binding
	}{
		{"stale-account", []mcpdirectory.Binding{staleAccount}},
		{"stale-server", []mcpdirectory.Binding{staleServer}},
		{"duplicate", []mcpdirectory.Binding{bindingA, bindingA}},
		{"disabled", []mcpdirectory.Binding{disabled}},
		{"unknown", []mcpdirectory.Binding{unknown}},
		{"swapped", []mcpdirectory.Binding{swapped}},
		{"empty", nil},
	} {
		if capture, err := s.RemoteMCPCaptureAt(ctx, 0, digest, profile, test.bindings); capture != nil || err != mcpgrant.ErrGrant {
			t.Fatal(test.name + " binding was accepted")
		}
	}
	capture, err := s.RemoteMCPCaptureAt(ctx, 0, digest, profile, []mcpdirectory.Binding{bindingA, bindingB})
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if status := s.Status(); status.Revision != 0 || status.Pending || status.Err != nil {
		t.Fatal("refused captures queued writes or changed revision")
	}
}

func importID(n int) string { return fmt.Sprintf("%032x", n+1) }

func rawImportServer(t *testing.T, v *Vault, id, name, profile string) {
	t.Helper()
	v.Targets[profile] = vaulttest.Target(t)
	v.Servers[id] = Server{Name: name, Accounts: map[string]string{"main": profile}}
}

func hasConflict(conflicts []ImportConflict, kind, subject string) bool {
	for _, conflict := range conflicts {
		if conflict.Kind == kind && (subject == "" || conflict.Subject == subject) {
			return true
		}
	}
	return false
}

func TestOwnerImportConflictKindsRefuseWholePlan(t *testing.T) {
	fx := newImportFixture(t, []byte("synthetic-global-value"))
	ref := vaulttest.DirectoryRef(t, 9)
	alphaMain := fx.source.Servers[fx.alpha].Accounts["main"]
	cases := []struct {
		name, kind, subject string
		linked              bool
		mutate              func(*Vault)
	}{
		{"server id", ConflictServerID, "production", true, func(v *Vault) { rawImportServer(t, v, fx.alpha, "unrelated", importID(500)) }},
		{"server name", ConflictServerName, "staging", true, func(v *Vault) { rawImportServer(t, v, importID(1), "staging", importID(500)) }},
		{"account id", ConflictAccountID, "production/main", true, func(v *Vault) { rawImportServer(t, v, importID(1), "mine", alphaMain) }},
		{"secret id", ConflictSecretID, "token", true, func(v *Vault) { v.Secrets[fx.tokenID] = SecretBinding{Name: "other", Ref: ref} }},
		{"secret name", ConflictSecretName, "token", true, func(v *Vault) { v.Secrets[importID(1)] = SecretBinding{Name: "token", Ref: ref} }},
		{"server limit", ConflictServerLimit, "", true, func(v *Vault) {
			for n := 0; n < 63; n++ {
				rawImportServer(t, v, importID(n), fmt.Sprintf("srv%d", n), importID(500+n))
			}
		}},
		{"account limit", ConflictAccountLimit, "", true, func(v *Vault) {
			base, accounts := vaulttest.Target(t), make(map[string]string)
			for n := 0; n < 63; n++ {
				v.Targets[importID(500+n)], accounts[fmt.Sprintf("acc%d", n)] = record.OwnTarget(base), importID(500+n)
			}
			v.Servers[importID(1)] = Server{Name: "wide", Accounts: accounts}
		}},
		{"secret limit", ConflictSecretLimit, "", true, func(v *Vault) {
			for n := 0; n < 126; n++ {
				v.Secrets[importID(n)] = SecretBinding{Name: fmt.Sprintf("s%d", n), Ref: ref}
			}
		}},
		{"pending intent", ConflictPendingIntent, "", true, func(v *Vault) {
			if _, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "queued", MediaType: "text/plain", Value: []byte("synthetic queued")}); err != nil {
				t.Fatal(err)
			}
		}},
		{"unlinked store", ConflictUnlinkedStore, "", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := importDestination(t, tc.linked, tc.mutate)
			conflicts, err := s.ImportConflicts(fx.imported)
			if err != nil || !hasConflict(conflicts, tc.kind, tc.subject) {
				t.Fatalf("missing %s conflict: %v", tc.kind, conflicts)
			}
			if err := s.ApplyOwnerImportDirectory(fx.imported); err != ErrImportConflict {
				t.Fatal("conflicting import was applied")
			}
			if s.Status().Revision != 0 {
				t.Fatal("refused import changed the revision")
			}
		})
	}
	t.Run("directory version", func(t *testing.T) {
		s := newSession(core.New(), nil, func() {})
		t.Cleanup(s.Discard)
		conflicts, err := s.ImportConflicts(fx.imported)
		if err != nil || !hasConflict(conflicts, ConflictDirectoryVersion, "") || s.ApplyOwnerImportDirectory(fx.imported) != ErrImportConflict {
			t.Fatal("version 1 destination was not refused")
		}
	})
}

func TestOwnerImportRefusalLeavesDestinationUntouched(t *testing.T) {
	fx := newImportFixture(t, []byte("synthetic-global-value"))
	var existing Target
	s := importDestination(t, true, func(v *Vault) {
		// Only "staging" (the second server by name) collides.
		rawImportServer(t, v, importID(1), "staging", importID(500))
		existing = record.OwnTarget(v.Targets[importID(500)])
	})
	conflicts, err := s.ImportConflicts(fx.imported)
	if err != nil || len(conflicts) != 1 || conflicts[0] != (ImportConflict{Kind: ConflictServerName, Subject: "staging"}) {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if err := s.ApplyOwnerImportDirectory(fx.imported); err != ErrImportConflict {
		t.Fatal("partially conflicting plan was not refused")
	}
	inspectSession(s, func(v *Vault) {
		if len(v.Servers) != 1 || len(v.Targets) != 1 || v.Servers[importID(1)].Name != "staging" || !sameImportedTarget(v.Targets[importID(500)], existing) {
			t.Fatal("refusal merged part of the plan or overwrote the destination")
		}
	})
	if s.Status().Revision != 0 {
		t.Fatal("refusal bumped the revision")
	}
}

func TestOwnerImportUnsupportedValuesAreConflicts(t *testing.T) {
	for _, value := range [][]byte{{0xff, 0xfe}, []byte("a\x00b")} {
		fx := newImportFixture(t, value)
		preview := fx.imported.Preview()
		if !hasConflict(preview.Conflicts, ConflictValueUnsupported, "token") || len(preview.Conflicts) != 1 {
			t.Fatal("preview did not flag the unsupported value")
		}
		s := importDestination(t, true, nil)
		conflicts, err := s.ImportConflicts(fx.imported)
		if err != nil || !hasConflict(conflicts, ConflictValueUnsupported, "token") {
			t.Fatal("session conflicts omitted the unsupported value")
		}
		if _, err := fx.imported.SecretChange(0); err == nil {
			t.Fatal("unsupported value became an owner change")
		}
		if s.ApplyOwnerImportDirectory(fx.imported) != ErrImportConflict || s.Status().Revision != 0 {
			t.Fatal("plan with an unsupported value was applied")
		}
	}
}

func TestVerifyOwnerImportDirectoryDetectsLaterEdits(t *testing.T) {
	fx := newImportFixture(t, []byte("synthetic-global-value"))
	accounts := fx.source.Servers[fx.alpha].Accounts
	retarget := func(profile string, change func(*Target)) func(*Vault) {
		return func(v *Vault) {
			target := record.OwnTarget(v.Targets[profile])
			change(&target)
			v.Targets[profile] = target
		}
	}
	cases := []struct {
		name string
		edit func(*Vault)
	}{
		{"server renamed", func(v *Vault) {
			server := v.Servers[fx.alpha]
			server.Name = "renamed"
			v.Servers[fx.alpha] = server
		}},
		{"account user", retarget(accounts["main"], func(x *Target) { x.User = "changed" })},
		{"account password", retarget(accounts["deploy"], func(x *Target) { x.Password = []byte("synthetic-replaced-password") })},
		{"account private key", retarget(accounts["main"], func(x *Target) { x.PrivateKey = vaulttest.Target(t).PrivateKey })},
		{"server removed", func(v *Vault) {
			delete(v.Servers, fx.alpha)
			for _, profile := range accounts {
				delete(v.Targets, profile)
			}
		}},
	}
	if (&Session{}).VerifyOwnerImportDirectory(nil) != ErrImportInvalid {
		t.Fatal("nil import was accepted")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := importDestination(t, true, nil)
			if err := s.ApplyOwnerImportDirectory(fx.imported); err != nil {
				t.Fatal(err)
			}
			if err := s.VerifyOwnerImportDirectory(fx.imported); err != nil {
				t.Fatalf("exact import failed verification: %v", err)
			}
			if err := s.Apply(func(v *Vault) error { tc.edit(v); return nil }); err != nil {
				t.Fatal(err)
			}
			if err := s.VerifyOwnerImportDirectory(fx.imported); err != ErrImportChanged {
				t.Fatalf("later edit was not detected: %v", err)
			}
		})
	}
}

func TestSessionMetadataListsSortedApprovalsNotAliased(t *testing.T) {
	v, _ := vaulttest.OwnerStoreFixture(t)
	for _, name := range []string{"beta", "alpha"} {
		rec := approval.Record{Name: name, Path: approvalPath(t, name), Hash: strings.Repeat("ab", 32)}
		if err := v.ApproveApplication(rec, ""); err != nil {
			t.Fatal(err)
		}
	}
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	t.Run("metadata lists approvals sorted by name", func(t *testing.T) {
		metadata, err := s.Metadata()
		if err != nil {
			t.Fatal(err)
		}
		if len(metadata.Approvals) != 2 || metadata.Approvals[0].Name != "alpha" || metadata.Approvals[1].Name != "beta" {
			t.Fatal("session metadata did not list approvals sorted by name")
		}
	})
	t.Run("caller mutation cannot alias the live approval set", func(t *testing.T) {
		metadata, err := s.Metadata()
		if err != nil {
			t.Fatal(err)
		}
		metadata.Approvals[0].Name = "caller-mutated"
		metadata.Approvals[0].Path = "caller-mutated"
		again, err := s.Metadata()
		if err != nil || again.Approvals[0].Name != "alpha" || again.Approvals[0].Path == "caller-mutated" {
			t.Fatal("approval metadata was aliased to the live approval set")
		}
		if s.state.Approvals["alpha"].Name != "alpha" {
			t.Fatal("caller mutation reached the live approval set")
		}
	})
}

func approvalPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}
