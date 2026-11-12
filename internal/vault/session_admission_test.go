package vault

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

func TestOwnerQueueAdmissionIsRevisionLockedAndDoesNotEdit(t *testing.T) {
	s := newSession(NewDirectory(), func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	called := false
	admit := func() error {
		called = true
		if s.mu.TryLock() {
			s.mu.Unlock()
			t.Fatal("owner queue admission did not retain the revision lock")
		}
		return nil
	}
	if err := s.AdmitAt(1, admit); !errors.Is(err, ErrOwnerRevision) || called {
		t.Fatal("stale queue admission executed its callback")
	}
	if err := s.AdmitAt(0, admit); err != nil || !called || s.Status().Revision != 0 {
		t.Fatal("queue admission changed the database or refused its displayed revision")
	}
	if err := s.Apply(func(*Vault) error { return nil }); err != nil {
		t.Fatal(err)
	}
	called = false
	if err := s.AdmitAt(0, admit); !errors.Is(err, ErrOwnerRevision) || called {
		t.Fatal("an intervening edit did not invalidate queue admission")
	}
	failure := errors.New("synthetic admission refusal")
	if err := s.AdmitAt(1, func() error { return failure }); !errors.Is(err, failure) || s.Status().Revision != 1 {
		t.Fatal("queue callback failure changed the database revision")
	}
}

func TestOwnerQueueAdmissionRejectsNilClosingAndClosed(t *testing.T) {
	s := newSession(NewDirectory(), func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	if err := s.AdmitAt(0, nil); err == nil {
		t.Fatal("nil queue callback accepted")
	}
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	called := false
	if err := s.AdmitAt(0, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("closing session admitted new owner work")
	}
	s.Discard()
	if err := s.AdmitAt(0, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("closed session admitted new owner work")
	}
}

func TestZeroValueSessionRotationSnapshotIsMetadataOnly(t *testing.T) {
	s := &Session{}
	if info, err := s.RotationSnapshot(); err != nil || !reflect.DeepEqual(info, RotationInfo{}) {
		t.Fatalf("zero-value snapshot = (%+v, %v), want zero info and nil error", info, err)
	}
	if _, err := s.PrepareKeyRotationAt(0, "server", "account"); !errors.Is(err, ErrOwnerRevision) {
		t.Fatalf("zero-value rotation preparation error = %v, want ErrOwnerRevision", err)
	}
	if _, _, err := s.RotationMaterialAt(0, 0); !errors.Is(err, ErrOwnerRevision) {
		t.Fatalf("zero-value rotation material error = %v, want ErrOwnerRevision", err)
	}
	if s.state != nil || s.revision != 0 || s.saved != 0 || s.closed || s.closing {
		t.Fatal("zero-value rotation calls mutated session state")
	}

	for _, field := range []string{"closed", "closing"} {
		t.Run(field, func(t *testing.T) {
			closed := &Session{}
			if field == "closed" {
				closed.closed = true
			} else {
				closed.closing = true
			}
			if _, err := closed.RotationSnapshot(); err == nil {
				t.Fatalf("%s session snapshot succeeded", field)
			}
		})
	}
}

type agentSourceFixture struct {
	session  *Session
	profile  string
	revision uint64
	digest   [32]byte
}

func newAgentSourceFixture(t *testing.T) agentSourceFixture {
	state, _ := directoryFixture(t)
	const revision = 7
	digest := [32]byte{1}
	return agentSourceFixture{
		session: &Session{state: state, revision: revision, saved: revision, savedCipher: digest},
		profile: "production", revision: revision, digest: digest,
	}
}

func (f *agentSourceFixture) confirmHealthyChange() {
	f.revision++
	f.digest = [32]byte{byte(f.revision)}
	f.session.revision, f.session.saved = f.revision, f.revision
	f.session.savedCipher = f.digest
}

type agentSSHMaterial struct {
	Config   *ssh.ClientConfig
	Address  string
	Scope    string
	Revision uint64
	Guard    *outputguard.Snapshot
}

func (f *agentSourceFixture) source() (agentSSHMaterial, error) {
	config, address, scope, err := f.session.AgentSSHAt(f.revision, f.digest, f.profile)
	if err != nil {
		return agentSSHMaterial{}, errors.New("synthetic source unavailable")
	}
	guard, err := f.session.OutputGuardAt(f.revision, f.digest)
	if err != nil {
		return agentSSHMaterial{}, errors.New("synthetic guard unavailable")
	}
	return agentSSHMaterial{Scope: scope, Revision: f.revision, Config: config, Address: address, Guard: guard}, nil
}

func TestAgentSSHRejectsUnconfirmedOrIneligibleState(t *testing.T) {
	for _, test := range []struct {
		name         string
		edit         func(*agentSourceFixture)
		wantRevision uint64
		wantDigest   [32]byte
	}{
		{"revision", nil, 8, [32]byte{1}},
		{"unsaved", func(f *agentSourceFixture) { f.session.saved-- }, 7, [32]byte{1}},
		{"save-error", func(f *agentSourceFixture) { f.session.saveErr = errors.New("synthetic save failure") }, 7, [32]byte{1}},
		{"digest-mismatch", func(f *agentSourceFixture) { f.session.savedCipher[0]++ }, 7, [32]byte{1}},
		{"saved-digest-zero", func(f *agentSourceFixture) { f.session.savedCipher = [32]byte{} }, 7, [32]byte{1}},
		{"requested-digest-zero", nil, 7, [32]byte{}},
		{"human-only", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.Usage = "human"
			f.session.state.Targets[f.profile] = target
		}, 7, [32]byte{1}},
		{"proxy", func(f *agentSourceFixture) {
			target := f.session.state.Targets[f.profile]
			target.Proxy = &sshproxy.Config{Type: "socks5", Address: "127.0.0.1:1080"}
			f.session.state.Targets[f.profile] = target
		}, 7, [32]byte{1}},
		{"owner-pending", func(f *agentSourceFixture) { f.session.state.OwnerStore = &OwnerStore{Pending: &OwnerIntent{}} }, 7, [32]byte{1}},
		{"multiple-profiles", func(f *agentSourceFixture) {
			for id, server := range f.session.state.Servers {
				server.Accounts["secondary"] = f.profile
				f.session.state.Servers[id] = server
			}
		}, 7, [32]byte{1}},
		{"closed", func(f *agentSourceFixture) { f.session.closed = true }, 7, [32]byte{1}},
		{"closing", func(f *agentSourceFixture) { f.session.closing = true }, 7, [32]byte{1}},
		{"missing-state", func(f *agentSourceFixture) { f.session.state = nil }, 7, [32]byte{1}},
		{"unsupported-state-version", func(f *agentSourceFixture) { f.session.state.Version = 1 }, 7, [32]byte{1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentSourceFixture(t)
			if test.edit != nil {
				test.edit(&fixture)
			}
			config, address, scope, err := fixture.session.AgentSSHAt(test.wantRevision, test.wantDigest, fixture.profile)
			if err == nil || config != nil || address != "" || scope != "" {
				t.Fatal("unconfirmed or ineligible state exposed SSH material")
			}
		})
	}
}
