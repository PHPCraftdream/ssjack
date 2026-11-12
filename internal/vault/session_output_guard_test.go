package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

func TestLegacyGuardRefusesUnauthenticatedOrDirectoryState(t *testing.T) {
	for _, state := range []*Vault{nil, New(), NewDirectory()} {
		if snapshot, err := state.LegacyOutputGuard(context.Background(), "missing"); snapshot != nil || err != outputguard.ErrGuard {
			t.Fatal("unauthenticated legacy or directory state granted a capability")
		}
	}
	if snapshot, err := New().LegacyOutputGuard(nil, "missing"); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("legacy capture accepted a missing context")
	}
}

func TestCredentialGuardPrivatelyCapturesAllCredentialClasses(t *testing.T) {
	state := New()
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
			s := &Session{state: New(), revision: 7, saved: 7, savedCipher: digest}
			test.edit(s)
			if snapshot, err := s.OutputGuardAt(7, digest); snapshot != nil || err != outputguard.ErrGuard {
				t.Fatal("unconfirmed state granted a guard capability or exposed diagnostics")
			}
		})
	}
	s := &Session{state: New()}
	if snapshot, err := s.OutputGuardAt(0, [32]byte{}); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("missing authenticated ciphertext evidence was accepted")
	}
	if snapshot, err := (*Session)(nil).OutputGuardAt(0, digest); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("nil session was accepted")
	}
}

func TestCredentialGuardCapturesBothPendingRotationKeys(t *testing.T) {
	state := NewDirectory()
	state.Targets["active"] = Target{PrivateKey: []byte("synthetic-active-key")}
	state.Rotation = &RotationJournal{
		Phase:      RotationPrepared,
		Original:   Target{PrivateKey: []byte("synthetic-retained-old-key")},
		NewPrivate: []byte("synthetic-pending-new-key"),
	}
	snapshot, err := credentialGuard(state)
	if err != nil {
		t.Fatal(err)
	}
	state.Close()
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("synthetic-active-key|synthetic-retained-old-key|synthetic-pending-new-key")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if result.String() != "[REDACTED]|[REDACTED]|[REDACTED]" {
		t.Fatal("pending rotation credential was not masked after vault buffers were cleared")
	}
}

func TestCredentialGuardCapturesOldKeyAfterCommitAndNotArchivedArtifact(t *testing.T) {
	state := NewDirectory()
	state.Targets["active"] = Target{PrivateKey: []byte("synthetic-current-new-key")}
	state.Rotation = &RotationJournal{
		Phase:      RotationComplete,
		Original:   Target{PrivateKey: []byte("synthetic-retained-old-key")},
		NewPrivate: []byte("synthetic-current-new-key"),
	}
	snapshot, err := credentialGuard(state)
	if err != nil {
		t.Fatal(err)
	}
	state.Close()
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("synthetic-retained-old-key|synthetic-current-new-key|synthetic-archived-only-key")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if result.String() != "[REDACTED]|[REDACTED]|synthetic-archived-only-key" {
		t.Fatal("completed journal keys or archive boundary were not handled as expected")
	}
}
func TestCredentialGuardRefusesWholeOversizedCredentialSet(t *testing.T) {
	state := New()
	state.Targets["large"] = Target{PrivateKey: make([]byte, outputguard.MaxPatternSize+1)}
	if snapshot, err := credentialGuard(state); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("oversized credential was truncated or omitted")
	}
	state.Targets = nil
	state.RemoteMCP = mcpdirectory.New()
	account := mcpdirectory.Account{}
	for range outputguard.MaxPatterns + 1 {
		account.Headers = append(account.Headers, mcpdirectory.Header{Value: []byte("synthetic")})
	}
	state.RemoteMCP.Accounts["many"] = account
	if snapshot, err := credentialGuard(state); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("credential count overflow was truncated")
	}
}

func TestRotationJournalCodecRoundTripsPreparedCancelledAndComplete(t *testing.T) {
	public, private := rotationTestIdentity(t)
	defer clear(public)
	defer clear(private)
	for _, phase := range []string{RotationPrepared, RotationCancelled, RotationComplete} {
		t.Run(phase, func(t *testing.T) {
			v, server := directoryFixture(t)
			old := ownTarget(v.Targets["production"])
			defer clear(old.PrivateKey)
			journal := &RotationJournal{
				ID: "0102030405060708090a0b0c0d0e0f10", PlanID: 3, BaseRevision: 7,
				Phase: phase, ServerID: server, Account: "main", Profile: "production",
			}
			if phase == RotationCancelled {
				journal.Original = Target{}
			} else {
				journal.Original = old
				journal.NewPrivate = append([]byte(nil), private...)
				journal.NewPublic = append([]byte(nil), public...)
				journal.OldPublic = testPublic(t, old.PrivateKey)
			}
			if phase == RotationComplete {
				current := v.Targets["production"]
				clear(current.PrivateKey)
				current.PrivateKey = append([]byte(nil), private...)
				v.Targets["production"] = current
				journal.CommitRevision = 0
				journal.CommitDigest = "0101010101010101010101010101010101010101010101010101010101010101"
			}
			v.Rotation = journal
			if phase == RotationCancelled {
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
				if decoded.Rotation == nil || decoded.Rotation.Phase != RotationCancelled || !rotationTargetEmpty(decoded.Rotation.Original) {
					t.Fatal("cancelled journal did not round-trip without material")
				}
				info := rotationInfo(decoded.Rotation)
				if info.ID != journal.ID || info.PlanID != journal.PlanID || info.BaseRevision != journal.BaseRevision || info.ServerID != server || info.Account != journal.Account || info.Profile != journal.Profile || info.Address != "" || info.User != "" || info.Usage != "" || len(info.HostKeys) != 0 || len(info.OldPublic) != 0 || len(info.NewPublic) != 0 {
					t.Fatal("cancelled rotation metadata exposed scrubbed target details")
				}
				return
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
			if decoded.Rotation == nil || decoded.Rotation.Phase != phase || decoded.Rotation.PlanID != 3 {
				t.Fatal("rotation identity or phase changed during round-trip")
			}
			if !bytes.Equal(decoded.Rotation.Original.PrivateKey, old.PrivateKey) || !bytes.Equal(decoded.Rotation.NewPrivate, private) || !bytes.Equal(decoded.Rotation.NewPublic, public) || !bytes.Equal(decoded.Rotation.OldPublic, journal.OldPublic) {
				t.Fatal("rotation round-trip lost retained old/new key material")
			}
			if phase != RotationComplete {
				return
			}
			if err := decoded.RenameServer(server, "renamed-after-completion"); err != nil {
				t.Fatal(err)
			}
			unrelated := ownTarget(decoded.Targets["production"])
			defer clear(unrelated.PrivateKey)
			unrelated.User = "unrelated-account"
			if err := decoded.SetAccount(server, "backup", unrelated); err != nil {
				t.Fatal(err)
			}
			updated, err := marshal(decoded)
			if err != nil {
				t.Fatalf("completed history blocked unrelated edits: %v", err)
			}
			defer clear(updated)
			reloaded, err := unmarshal(updated)
			if err != nil {
				t.Fatalf("completed history did not survive edited round-trip: %v", err)
			}
			reloaded.Close()
		})
	}
}
