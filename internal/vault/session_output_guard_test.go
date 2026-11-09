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
