package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/vaulttest"
)

func TestOwnerQueueAdmissionIsRevisionLockedAndDoesNotEdit(t *testing.T) {
	s := newSession(core.NewDirectory(), func(context.Context, []byte) error { return nil }, func() {})
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
	s := newSession(core.NewDirectory(), func(context.Context, []byte) error { return nil }, func() {})
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
	lent := false
	if err := s.WithRotationMaterialAt(0, 0, func(Target, Target) error { lent = true; return nil }); !errors.Is(err, ErrOwnerRevision) || lent {
		t.Fatalf("zero-value rotation material = (%v, lent=%v), want ErrOwnerRevision and no callback", err, lent)
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
	state, _ := vaulttest.DirectoryFixture(t)
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
func TestClearRotationTargetWipesSecretBuffers(t *testing.T) {
	key, password := []byte("private-key"), []byte("password")
	target := Target{PrivateKey: key, Password: password}
	clearRotationTarget(&target)
	for name, buffer := range map[string][]byte{"private key": key, "password": password} {
		for _, b := range buffer {
			if b != 0 {
				t.Fatalf("%s buffer not wiped: %v", name, buffer)
			}
		}
	}
}

func TestWithRotationMaterialAtRequiresCallback(t *testing.T) {
	if err := (&Session{}).WithRotationMaterialAt(0, 0, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
}

func TestDiscardRotationJournalDestroysMaterialAndCancels(t *testing.T) {
	original, replacement := []byte("old-private"), []byte("new-private")
	j := &RotationJournal{
		Phase:      core.RotationUnknown,
		Original:   Target{PrivateKey: original},
		NewPrivate: replacement,
		NewPublic:  []byte("new-public"),
		OldPublic:  []byte("old-public"),
	}
	discardRotationJournal(j)
	if j.Phase != core.RotationCancelled || !core.RotationTargetEmpty(j.Original) || len(j.NewPrivate)+len(j.NewPublic)+len(j.OldPublic) != 0 {
		t.Fatalf("journal retains material or phase: %+v", j)
	}
	for name, buffer := range map[string][]byte{"original": original, "replacement": replacement} {
		for _, b := range buffer {
			if b != 0 {
				t.Fatalf("%s private key not wiped: %v", name, buffer)
			}
		}
	}
}

func retirementSession() *Session {
	account := Target{Address: "host.invalid:22", User: "deploy"}
	original, current := account, account
	original.PrivateKey = []byte("old-private")
	current.PrivateKey = []byte("new-private")
	return &Session{revision: 7, state: &Vault{
		Targets: map[string]Target{"main": current},
		Rotation: &RotationJournal{
			PlanID: 3, Phase: core.RotationComplete, Profile: "main", Original: original,
			NewPrivate: []byte("new-private"), OldPublic: []byte("old-public"), NewPublic: []byte("new-public"),
		},
	}}
}

func TestRetirementMaterialLendsCommittedKeyAndWipesTheLoan(t *testing.T) {
	s := retirementSession()
	var lent []byte
	err := s.WithRetirementMaterialAt(7, 3, func(current Target, oldPublic, newPublic []byte) error {
		if string(current.PrivateKey) != "new-private" || current.Address != "host.invalid:22" || current.User != "deploy" {
			t.Fatalf("lent credential = %+v, want the committed replacement key", current)
		}
		if string(oldPublic) != "old-public" || string(newPublic) != "new-public" {
			t.Fatalf("lent public keys = %q, %q", oldPublic, newPublic)
		}
		lent = current.PrivateKey
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lent, make([]byte, len(lent))) {
		t.Fatalf("lent private key not wiped: %q", lent)
	}
	if string(s.state.Targets["main"].PrivateKey) != "new-private" || string(s.state.Rotation.NewPrivate) != "new-private" {
		t.Fatal("wiping the loan damaged the stored credential")
	}
	sentinel := errors.New("remote failed")
	if err := s.WithRetirementMaterialAt(7, 3, func(Target, []byte, []byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("callback error = %v", err)
	}
}

func TestRetirementMaterialRefusesAnythingButTheExactCompletedRotation(t *testing.T) {
	for name, mutate := range map[string]func(*Session) (revision, plan uint64){
		"stale revision": func(*Session) (uint64, uint64) { return 6, 3 },
		"wrong plan":     func(*Session) (uint64, uint64) { return 7, 4 },
		"verified, not committed": func(s *Session) (uint64, uint64) {
			s.state.Rotation.Phase = core.RotationVerified
			return 7, 3
		},
		"archived": func(s *Session) (uint64, uint64) {
			s.state.Rotation.Phase = core.RotationArchived
			return 7, 3
		},
		"credential changed after completion": func(s *Session) (uint64, uint64) {
			target := s.state.Targets["main"]
			target.PrivateKey = []byte("later-private")
			s.state.Targets["main"] = target
			return 7, 3
		},
		"endpoint changed after completion": func(s *Session) (uint64, uint64) {
			target := s.state.Targets["main"]
			target.Address = "elsewhere.invalid:22"
			s.state.Targets["main"] = target
			return 7, 3
		},
		"another profile still uses the old key on this account": func(s *Session) (uint64, uint64) {
			s.state.Targets["agent"] = Target{Address: "host.invalid:22", User: "deploy", PrivateKey: []byte("old-private")}
			return 7, 3
		},
		"closed session": func(s *Session) (uint64, uint64) {
			s.closed = true
			return 7, 3
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := retirementSession()
			revision, plan := mutate(s)
			lent := false
			err := s.WithRetirementMaterialAt(revision, plan, func(Target, []byte, []byte) error { lent = true; return nil })
			if err == nil || lent {
				t.Fatalf("retirement material lent: err=%v lent=%v", err, lent)
			}
		})
	}
}

func TestRetirementMaterialIgnoresOldKeyOnOtherAccounts(t *testing.T) {
	s := retirementSession()
	s.state.Targets["other-host"] = Target{Address: "other.invalid:22", User: "deploy", PrivateKey: []byte("old-private")}
	s.state.Targets["other-user"] = Target{Address: "host.invalid:22", User: "backup", PrivateKey: []byte("old-private")}
	if err := s.WithRetirementMaterialAt(7, 3, func(Target, []byte, []byte) error { return nil }); err != nil {
		t.Fatalf("old key on a different remote account blocked retirement: %v", err)
	}
	if err := s.WithRetirementMaterialAt(7, 3, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
}
func TestRotationRestartUsesFreshSessionRevisionForVerifiedAndCommittedRecovery(t *testing.T) {
	public, private := vaulttest.RotationIdentity(t)
	defer clear(public)
	defer clear(private)
	for _, phase := range []string{core.RotationVerified, core.RotationCommitted} {
		t.Run(phase, func(t *testing.T) {
			v, server := vaulttest.DirectoryFixture(t)
			old := record.OwnTarget(v.Targets["production"])
			defer clear(old.PrivateKey)
			journal := &RotationJournal{
				ID: "0102030405060708090a0b0c0d0e0f10", PlanID: 4, BaseRevision: 7,
				Phase: phase, ServerID: server, Account: "main", Profile: "production",
				Original: record.OwnTarget(old), NewPrivate: append([]byte(nil), private...),
				NewPublic: append([]byte(nil), public...), OldPublic: vaulttest.Public(t, old.PrivateKey),
			}
			if phase == core.RotationCommitted {
				current := v.Targets["production"]
				clear(current.PrivateKey)
				current.PrivateKey = append([]byte(nil), private...)
				v.Targets["production"] = current
				journal.CommitRevision = 0
			}
			v.Rotation = journal
			payload, err := core.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := core.Unmarshal(payload)
			clear(payload)
			if err != nil {
				t.Fatal(err)
			}
			digest := [32]byte{1}
			session := newSession(restarted, func(context.Context, []byte) error { return nil }, func() {})
			session.saveDigest = func() [32]byte { return digest }
			session.savedCipher = digest
			defer session.Discard()
			if status := session.Status(); status.Revision != 0 || status.SavedRevision != 0 {
				t.Fatal("restarted session did not begin at revision zero")
			}
			if phase == core.RotationVerified {
				if err := session.CommitRotationAt(0, 4); err != nil {
					t.Fatalf("verified recovery rejected fresh session revision: %v", err)
				}
				if err := session.Flush(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := session.CompleteRotationAt(1, 4, digest); err != nil {
					t.Fatalf("committed recovery rejected fresh session revision: %v", err)
				}
			} else if err := session.CompleteRotationAt(0, 4, digest); err != nil {
				t.Fatalf("already-committed recovery rejected fresh session revision: %v", err)
			}
			if err := session.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			info, err := session.RotationSnapshot()
			if err != nil || info.Phase != core.RotationComplete {
				t.Fatalf("recovery did not complete: phase=%q err=%v", info.Phase, err)
			}
		})
	}
}

func TestArchiveRotationCopiesSavedCiphertextAndQueuesReceiptTombstone(t *testing.T) {
	state, server := vaulttest.DirectoryFixture(t)
	old := record.OwnTarget(state.Targets["production"])
	defer clear(old.PrivateKey)
	public, private := vaulttest.RotationIdentity(t)
	defer clear(public)
	defer clear(private)
	current := state.Targets["production"]
	clear(current.PrivateKey)
	current.PrivateKey = append([]byte(nil), private...)
	state.Targets["production"] = current
	state.Rotation = &RotationJournal{
		ID: "0102030405060708090a0b0c0d0e0f10", PlanID: 3, BaseRevision: 7,
		CommitRevision: 0,
		Phase:          core.RotationComplete, ServerID: server, Account: "main", Profile: "production",
		Original: old, NewPrivate: append([]byte(nil), private...), NewPublic: append([]byte(nil), public...),
		OldPublic:    vaulttest.Public(t, old.PrivateKey),
		CommitDigest: "0101010101010101010101010101010101010101010101010101010101010101",
	}
	path := filepath.Join(t.TempDir(), "vault")
	ciphertext := []byte("synthetic saved ciphertext from completed rotation")
	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	currentDigest := sha256.Sum256(ciphertext)
	currentHex := fmt.Sprintf("%x", currentDigest)
	if currentHex == state.Rotation.CommitDigest {
		t.Fatal("test requires historical commit proof to differ from current ciphertext")
	}
	var savedPayload []byte
	session := newSession(state, func(_ context.Context, payload []byte) error {
		clear(savedPayload)
		savedPayload = append(savedPayload, payload...)
		return nil
	}, func() {})
	session.revision, session.saved = 0, 0
	session.savedCipher = currentDigest
	defer session.Discard()
	defer clear(savedPayload)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id := state.Rotation.ID
	for _, request := range []struct {
		revision uint64
		planID   uint64
		id       string
	}{{1, 3, id}, {0, 2, id}, {0, 3, "0102030405060708090a0b0c0d0e0f11"}} {
		if _, err := session.ArchiveRotationAt(ctx, path, request.revision, request.planID, request.id); !errors.Is(err, ErrOwnerRevision) {
			t.Fatal("stale revision or mismatched journal identity was archived")
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("rejected archive requests changed the file inventory")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := session.ArchiveRotationAt(cancelled, path, 0, 3, id); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled archive request was accepted")
	}
	entries, err = os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("cancelled archive request changed the file inventory")
	}
	info, err := session.ArchiveRotationAt(ctx, path, 0, 3, id)
	if err != nil {
		t.Fatal(err)
	}
	if info.Phase != core.RotationArchived || info.ID != id || info.PlanID != 3 || info.ServerID != server || info.Account != "main" || info.Profile != "production" || info.RecoveryPath == "" || info.RecoveryDigest != currentHex {
		t.Fatal("archive receipt lost stable rotation identity or current ciphertext digest")
	}
	archive, err := store.ReadEncoded(info.RecoveryPath)
	if err != nil || !bytes.Equal(archive, ciphertext) {
		t.Fatal("encrypted archive does not match the exact saved database ciphertext")
	}
	if err := session.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	persisted, err := core.Unmarshal(savedPayload)
	if err != nil {
		t.Fatal(err)
	}
	defer persisted.Close()
	journal := persisted.Rotation
	if journal == nil || journal.Phase != core.RotationArchived || journal.ID != id || journal.PlanID != 3 || journal.ServerID != server || journal.Account != "main" || journal.Profile != "production" || journal.RecoveryPath != info.RecoveryPath || journal.RecoveryDigest != currentHex || !core.RotationTargetEmpty(journal.Original) || len(journal.NewPrivate)+len(journal.NewPublic)+len(journal.OldPublic) != 0 {
		t.Fatal("queued tombstone did not retain the archive receipt and clear private material")
	}
	if got, err := store.ReadEncoded(path); err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatal("archival changed the current live database ciphertext")
	}
	if _, err := session.ArchiveRotationAt(ctx, path, 0, 3, id); !errors.Is(err, ErrOwnerRevision) {
		t.Fatal("repeat archival of the tombstone was accepted")
	}
	entries, err = os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 2 {
		t.Fatal("stale archive request changed the file inventory")
	}
}

func TestRotationJournalCodecRoundTripsPreparedCancelledAndComplete(t *testing.T) {
	public, private := vaulttest.RotationIdentity(t)
	defer clear(public)
	defer clear(private)
	for _, phase := range []string{core.RotationPrepared, core.RotationCancelled, core.RotationComplete} {
		t.Run(phase, func(t *testing.T) {
			v, server := vaulttest.DirectoryFixture(t)
			old := record.OwnTarget(v.Targets["production"])
			defer clear(old.PrivateKey)
			journal := &RotationJournal{
				ID: "0102030405060708090a0b0c0d0e0f10", PlanID: 3, BaseRevision: 7,
				Phase: phase, ServerID: server, Account: "main", Profile: "production",
			}
			if phase == core.RotationCancelled {
				journal.Original = Target{}
			} else {
				journal.Original = old
				journal.NewPrivate = append([]byte(nil), private...)
				journal.NewPublic = append([]byte(nil), public...)
				journal.OldPublic = vaulttest.Public(t, old.PrivateKey)
			}
			if phase == core.RotationComplete {
				current := v.Targets["production"]
				clear(current.PrivateKey)
				current.PrivateKey = append([]byte(nil), private...)
				v.Targets["production"] = current
				journal.CommitRevision = 0
				journal.CommitDigest = "0101010101010101010101010101010101010101010101010101010101010101"
			}
			v.Rotation = journal
			if phase == core.RotationCancelled {
				encoded, err := core.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(encoded)
				decoded, err := core.Unmarshal(encoded)
				if err != nil {
					t.Fatal(err)
				}
				defer decoded.Close()
				if decoded.Rotation == nil || decoded.Rotation.Phase != core.RotationCancelled || !core.RotationTargetEmpty(decoded.Rotation.Original) {
					t.Fatal("cancelled journal did not round-trip without material")
				}
				info := rotationInfo(decoded.Rotation)
				if info.ID != journal.ID || info.PlanID != journal.PlanID || info.BaseRevision != journal.BaseRevision || info.ServerID != server || info.Account != journal.Account || info.Profile != journal.Profile || info.Address != "" || info.User != "" || info.Usage != "" || len(info.HostKeys) != 0 || len(info.OldPublic) != 0 || len(info.NewPublic) != 0 {
					t.Fatal("cancelled rotation metadata exposed scrubbed target details")
				}
				return
			}
			encoded, err := core.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(encoded)
			decoded, err := core.Unmarshal(encoded)
			if err != nil {
				t.Fatal(err)
			}
			defer decoded.Close()
			if decoded.Rotation == nil || decoded.Rotation.Phase != phase || decoded.Rotation.PlanID != 3 {
				t.Fatal("rotation identity or phase changed during round-trip")
			}
			if !bytes.Equal(decoded.Rotation.Original.PrivateKey, old.PrivateKey) || !bytes.Equal(decoded.Rotation.NewPrivate, private) || !bytes.Equal(decoded.Rotation.NewPublic, public) || !bytes.Equal(decoded.Rotation.OldPublic, journal.OldPublic) {
				t.Fatal("rotation round-trip lost retained old/new key material")
			}
			if phase != core.RotationComplete {
				return
			}
			if err := decoded.RenameServer(server, "renamed-after-completion"); err != nil {
				t.Fatal(err)
			}
			unrelated := record.OwnTarget(decoded.Targets["production"])
			defer clear(unrelated.PrivateKey)
			unrelated.User = "unrelated-account"
			if err := decoded.SetAccount(server, "backup", unrelated); err != nil {
				t.Fatal(err)
			}
			updated, err := core.Marshal(decoded)
			if err != nil {
				t.Fatalf("completed history blocked unrelated edits: %v", err)
			}
			defer clear(updated)
			reloaded, err := core.Unmarshal(updated)
			if err != nil {
				t.Fatalf("completed history did not survive edited round-trip: %v", err)
			}
			reloaded.Close()
		})
	}
}

func TestCredentialGuardPrivatelyCapturesAllCredentialClasses(t *testing.T) {
	state := core.New()
	state.Targets["synthetic"] = Target{Password: []byte("ssh-password"), PrivateKey: []byte("private-key"), Proxy: &sshproxy.Config{Password: []byte("proxy-password")}}
	state.OwnerStore = &OwnerStore{Master: []byte("installation-master")}
	state.RemoteMCP = mcpdirectory.New()
	state.RemoteMCP.Accounts["disabled"] = mcpdirectory.Account{Enabled: false, Auth: mcpdirectory.Authentication{Secret: []byte("remote-auth")}, Headers: []mcpdirectory.Header{{Value: []byte("header-value")}}}
	digest := [32]byte{1}
	session := &Session{state: state, revision: 7, saved: 7, savedCipher: digest}
	snapshot, err := session.OutputGuardAt(7, digest)
	if err != nil {
		t.Fatal(err)
	}
	state.Close()
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &result)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("ssh-password|private-key|proxy-password|installation-master|remote-auth|header-value|public")
	for _, value := range input {
		if _, err := writer.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if result.String() != "[REDACTED]|[REDACTED]|[REDACTED]|[REDACTED]|[REDACTED]|[REDACTED]|public" {
		t.Fatal("snapshot lost a credential class or borrowed cleared input")
	}
}

func TestSessionGuardRequiresExactConfirmedPersistenceEvidence(t *testing.T) {
	digest := [32]byte{1}
	cases := []struct {
		name string
		edit func(*Session)
	}{
		{"closed", func(s *Session) { s.closed = true }},
		{"closing", func(s *Session) { s.closing = true }},
		{"missing-state", func(s *Session) { s.state = nil }},
		{"revision", func(s *Session) { s.revision++ }},
		{"unsaved", func(s *Session) { s.saved-- }},
		{"save-error", func(s *Session) { s.saveErr = errors.New("private diagnostic") }},
		{"digest", func(s *Session) { s.savedCipher[0]++ }},
		{"owner-pending", func(s *Session) { s.state.OwnerStore = &OwnerStore{Pending: &OwnerIntent{}} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			s := &Session{state: core.New(), revision: 7, saved: 7, savedCipher: digest}
			test.edit(s)
			if snapshot, err := s.OutputGuardAt(7, digest); snapshot != nil || err != outputguard.ErrGuard {
				t.Fatal("unconfirmed state granted a guard capability or exposed diagnostics")
			}
		})
	}
	s := &Session{state: core.New()}
	if snapshot, err := s.OutputGuardAt(0, [32]byte{}); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("missing authenticated ciphertext evidence was accepted")
	}
	if snapshot, err := (*Session)(nil).OutputGuardAt(0, digest); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("nil session was accepted")
	}
}
