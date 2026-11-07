package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

func captureSession(t *testing.T) (*Session, string, mcpdirectory.Binding, mcpdirectory.Binding, mcpdirectory.Binding, [32]byte) {
	t.Helper()
	state, server := directoryFixture(t)
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
			ctx := sessionTestContext(t)
			if capture, err := s.RemoteMCPCaptureAt(ctx, 0, digest, profile, []mcpdirectory.Binding{bindingA}); capture != nil || err != mcpgrant.ErrGrant {
				t.Fatal("unconfirmed state granted a capture or exposed diagnostics")
			}
		})
	}
	s, profile, bindingA, _, _, _ := captureSession(t)
	ctx := sessionTestContext(t)
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
	ctx := sessionTestContext(t)
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
	ctx := sessionTestContext(t)
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
