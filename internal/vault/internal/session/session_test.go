package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/vaulttest"
)

func TestSessionSerializesAndCoalescesOwnedSnapshots(t *testing.T) {
	state, server := vaulttest.DirectoryFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	persisted := make(chan string, 4)
	var calls, released atomic.Int32
	var payloads [][]byte
	s := newSession(state, func(ctx context.Context, payload []byte) error {
		v, err := core.Unmarshal(payload)
		if err != nil {
			return err
		}
		defer v.Close()
		name := v.Servers[server].Name
		payloads = append(payloads, payload)
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
			}
		}
		persisted <- name
		return nil
	}, func() { released.Add(1) })
	t.Cleanup(s.Discard)
	if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, "first") }); err != nil {
		t.Fatal(err)
	}
	ctx := vaulttest.Context(t)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("save worker did not start")
	}
	for _, name := range []string{"second", "third"} {
		if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, name) }); err != nil {
			t.Fatal(err)
		}
	}
	status := s.Status()
	if !status.Pending || status.Revision != 3 || status.SavedRevision != 0 {
		t.Fatal("pending revisions were reported as saved")
	}
	close(release)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || <-persisted != "first" || <-persisted != "third" {
		t.Fatal("save worker reordered snapshots or retained an obsolete queued revision")
	}
	for _, payload := range payloads {
		if !bytes.Equal(payload, make([]byte, len(payload))) {
			t.Fatal("completed plaintext snapshot was not cleared")
		}
	}
	if status := s.Status(); status.Pending || status.Revision != 3 || status.SavedRevision != 3 {
		t.Fatal("latest completed revision was not reported as saved")
	}
	if err := s.Close(ctx); err != nil || released.Load() != 1 {
		t.Fatal("session did not join the worker before releasing its unlock context")
	}
	if err := s.Apply(func(*Vault) error { return nil }); err == nil {
		t.Fatal("closed session accepted an edit")
	}
}

func TestSessionFailedFormsNeverQueueWrites(t *testing.T) {
	state, server := vaulttest.DirectoryFixture(t)
	var calls atomic.Int32
	s := newSession(state, func(context.Context, []byte) error { calls.Add(1); return nil }, func() {})
	t.Cleanup(s.Discard)
	cancelled := errors.New("form cancelled")
	if err := s.Apply(func(v *Vault) error {
		if err := v.RenameServer(server, "not-committed"); err != nil {
			return err
		}
		return cancelled
	}); !errors.Is(err, cancelled) {
		t.Fatal("cancelled form did not report cancellation")
	}
	if err := s.Apply(func(v *Vault) error { v.Version = 99; return nil }); err == nil {
		t.Fatal("invalid form was accepted")
	}
	if err := s.Flush(vaulttest.Context(t)); err != nil {
		t.Fatal(err)
	}
	if status := s.Status(); status.Revision != 0 || status.Pending || calls.Load() != 0 {
		t.Fatal("cancelled or invalid form changed state or saved a snapshot")
	}
	if state.Servers[server].Name != "production" {
		t.Fatal("failed candidate mutated the original in-memory state")
	}
}

func TestSessionSaveFailureKeepsChangesUntilExplicitRetry(t *testing.T) {
	state, server := vaulttest.DirectoryFixture(t)
	failure := errors.New("synthetic persistence failure")
	var calls, released atomic.Int32
	persisted := make(chan string, 1)
	s := newSession(state, func(_ context.Context, payload []byte) error {
		if calls.Add(1) == 1 {
			return failure
		}
		v, err := core.Unmarshal(payload)
		if err != nil {
			return err
		}
		defer v.Close()
		persisted <- v.Servers[server].Name
		return nil
	}, func() { released.Add(1) })
	t.Cleanup(s.Discard)
	ctx := vaulttest.Context(t)
	if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, "first") }); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); !errors.Is(err, failure) {
		t.Fatal("save failure was hidden")
	}
	if err := s.Close(ctx); !errors.Is(err, failure) || released.Load() != 0 {
		t.Fatal("failed close discarded unsaved state or released its key")
	}
	if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, "latest") }); err != nil {
		t.Fatal("session stopped accepting owner edits after save failure")
	}
	if status := s.Status(); !status.Pending || status.Revision != 2 || !errors.Is(status.Err, failure) {
		t.Fatal("failed pending state was not retained")
	}
	if err := s.Retry(); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if <-persisted != "latest" || calls.Load() != 2 {
		t.Fatal("explicit retry did not save the latest owner state")
	}
	if err := s.Close(ctx); err != nil || released.Load() != 1 {
		t.Fatal("recovered session did not close cleanly")
	}
}

func TestSessionCloseTimeoutDoesNotDiscardPendingState(t *testing.T) {
	state, server := vaulttest.DirectoryFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var released atomic.Int32
	s := newSession(state, func(ctx context.Context, _ []byte) error {
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func() { released.Add(1) })
	t.Cleanup(s.Discard)
	if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, "pending") }); err != nil {
		t.Fatal(err)
	}
	ctx := vaulttest.Context(t)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("save worker did not start")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Close(cancelled); !errors.Is(err, context.Canceled) || released.Load() != 0 {
		t.Fatal("close timeout lost pending data or the unlock context")
	}
	close(release)
	if err := s.Close(ctx); err != nil || released.Load() != 1 {
		t.Fatal("pending save could not finish after close timeout")
	}
}
func TestSavedCipherDigestRefusesUnavailableMetadata(t *testing.T) {
	v, _ := vaulttest.DirectoryFixture(t)
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	if _, err := s.SavedCipherDigest(); err == nil {
		t.Fatal("synthetic session fabricated a saved ciphertext digest")
	}
}

func TestCancelledSessionCloseKeepsWriterUntilItsWorkerJoins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ktav")
	if err := store.Commit(path, []byte("synthetic encrypted data"), nil); err != nil {
		t.Fatal(err)
	}
	role, err := store.ClaimRole(path)
	if err != nil {
		t.Fatal(err)
	}
	entered, proceed := make(chan struct{}), make(chan struct{})
	s := newSession(core.NewDirectory(), func(ctx context.Context, _ []byte) error {
		close(entered)
		select {
		case <-proceed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func() {})
	s.mu.Lock()
	s.writer = role
	s.mu.Unlock()
	defer s.Discard()
	defer close(proceed)
	if err := s.Apply(func(*Vault) error { return nil }); err != nil {
		t.Fatal(err)
	}
	wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	select {
	case <-entered:
	case <-wait.Done():
		t.Fatal("controlled save did not start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled close lost its outcome")
	}
	if foreign, err := store.ClaimRole(path); !errors.Is(err, store.ErrWriterRole) {
		if foreign != nil {
			foreign.Close()
		}
		t.Fatal("cancelled close released a writer with active work")
	}
}

func TestFailedSessionSaveKeepsItsWriterRoleUntilExplicitDiscard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ktav")
	if err := store.Commit(path, []byte("synthetic encrypted data"), nil); err != nil {
		t.Fatal(err)
	}
	role, err := store.ClaimRole(path)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("synthetic persistence refusal")
	s := newSession(core.NewDirectory(), func(context.Context, []byte) error { return failure }, func() {})
	s.mu.Lock()
	s.writer = role
	s.mu.Unlock()
	defer s.Discard()
	if err := s.Apply(func(*Vault) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(context.Background()); !errors.Is(err, failure) {
		t.Fatal("failed save was reported as a closed success")
	}
	if foreign, err := store.ClaimRole(path); !errors.Is(err, store.ErrWriterRole) {
		if foreign != nil {
			foreign.Close()
		}
		t.Fatal("failed close released the live writer claim")
	}
	s.Discard()
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreign, err := store.ClaimRole(path)
	if err != nil {
		t.Fatal("joined explicit discard retained the writer endpoint")
	}
	foreign.Close()
}

func TestOwnerRevisionRefusalIsAtomicBeforeMutation(t *testing.T) {
	v, server := vaulttest.DirectoryFixture(t)
	session := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(session.Discard)
	if err := session.ApplyAt(0, func(v *Vault) error { return v.RenameServer(server, "first") }); err != nil {
		t.Fatal(err)
	}
	called := false
	err := session.ApplyAt(0, func(v *Vault) error { called = true; return v.RenameServer(server, "stale-overwrite") })
	if !errors.Is(err, ErrOwnerRevision) || called {
		t.Fatal("stale owner revision reached a mutation")
	}
	metadata, status, _, err := session.MetadataSnapshot()
	if err != nil || status.Revision != 1 || len(metadata.Servers) != 1 || metadata.Servers[0].Name != "first" {
		t.Fatal("stale owner command changed the atomically observed revision")
	}
}

func selectionSession(t *testing.T, save func(context.Context, []byte) error) (*Session, string, string, mcpdirectory.Binding, [32]byte) {
	t.Helper()
	state, server := vaulttest.DirectoryFixture(t)
	profile, err := state.AccountProfile(server, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetAccount(server, "other", state.Targets[profile]); err != nil {
		t.Fatal(err)
	}
	other, err := state.AccountProfile(server, "other")
	if err != nil {
		t.Fatal(err)
	}
	state.RemoteMCP = mcpdirectory.New()
	remote, err := state.RemoteMCP.AddServer("remote", "https://selection.invalid/mcp")
	if err != nil {
		t.Fatal(err)
	}
	account, err := state.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remote, Name: "public", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "none"}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := state.RemoteMCP.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{1}
	session := newSession(state, save, func() {})
	t.Cleanup(session.Discard)
	session.mu.Lock()
	session.savedCipher = digest
	session.saveDigest = func() [32]byte { return digest }
	session.mu.Unlock()
	return session, profile, other, binding, digest
}

func TestRememberMCPPreferenceOwnsExactConfirmedChoiceAndEmptyScope(t *testing.T) {
	var calls atomic.Int32
	s, profile, other, binding, digest := selectionSession(t, func(context.Context, []byte) error { calls.Add(1); return nil })
	ctx := vaulttest.Context(t)
	selected := []mcpdirectory.Binding{binding}
	if err := s.RememberRemoteMCPAt(ctx, 0, digest, profile, selected); err != nil {
		t.Fatal(err)
	}
	selected[0].AccountRevision++
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	metadata, err := s.Metadata()
	if err != nil || !reflect.DeepEqual(metadata.RemoteMCP.Last[profile], []mcpdirectory.Binding{binding}) || len(metadata.RemoteMCP.Last[other]) != 0 || calls.Load() != 1 {
		t.Fatal("confirmed preference borrowed input, changed another profile or did not persist")
	}
	if err := s.RememberRemoteMCPAt(ctx, 1, digest, other, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	metadata, err = s.Metadata()
	if err != nil || metadata.RemoteMCP.Last[other] == nil || len(metadata.RemoteMCP.Last[other]) != 0 || len(metadata.RemoteMCP.Last[profile]) != 1 {
		t.Fatal("explicit empty preference was lost or changed another profile")
	}
}

func TestRememberMCPRefusesStaleCancelledUnknownAndOversizedChoicesWithoutWrites(t *testing.T) {
	var calls atomic.Int32
	s, profile, _, binding, digest := selectionSession(t, func(context.Context, []byte) error { calls.Add(1); return nil })
	ctx := vaulttest.Context(t)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	stale := binding
	stale.AccountRevision++
	for _, test := range []struct {
		ctx      context.Context
		revision uint64
		digest   [32]byte
		profile  string
		selected []mcpdirectory.Binding
	}{
		{ctx, 1, digest, profile, []mcpdirectory.Binding{binding}},
		{ctx, 0, [32]byte{2}, profile, []mcpdirectory.Binding{binding}},
		{ctx, 0, [32]byte{}, profile, nil},
		{cancelled, 0, digest, profile, nil},
		{nil, 0, digest, profile, nil},
		{ctx, 0, digest, "missing", nil},
		{ctx, 0, digest, profile, []mcpdirectory.Binding{stale}},
		{ctx, 0, digest, profile, []mcpdirectory.Binding{binding, binding}},
		{ctx, 0, digest, profile, make([]mcpdirectory.Binding, mcpdirectory.MaxSelections+1)},
	} {
		if s.RememberRemoteMCPAt(test.ctx, test.revision, test.digest, test.profile, test.selected) == nil {
			t.Fatal("invalid preference was admitted")
		}
	}
	if err := s.Flush(ctx); err != nil || calls.Load() != 0 || s.Status().Revision != 0 {
		t.Fatal("refused preferences queued writes or changed revision")
	}
}

func TestRememberMCPRefusesPendingOrFailedPersistence(t *testing.T) {
	for _, failed := range []bool{false, true} {
		started, release := make(chan struct{}), make(chan struct{})
		s, profile, _, binding, digest := selectionSession(t, func(ctx context.Context, _ []byte) error {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			if failed {
				return errors.New("synthetic private save diagnostic")
			}
			return nil
		})
		ctx := vaulttest.Context(t)
		if err := s.Apply(func(*Vault) error { return nil }); err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("save worker did not reach the controlled barrier")
		}
		err := s.RememberRemoteMCPAt(ctx, 1, digest, profile, []mcpdirectory.Binding{binding})
		close(release)
		if err == nil {
			t.Fatal("pending save granted preference admission")
		}
		flush := s.Flush(ctx)
		if !failed && flush != nil {
			t.Fatal("released save did not settle")
		}
		if failed && (flush == nil || s.RememberRemoteMCPAt(ctx, 1, digest, profile, nil) == nil) {
			t.Fatal("failed persistence granted preference admission")
		}
	}
}
func TestRemoteMCPRoundTripPreferencesAndOwnedMetadata(t *testing.T) {
	v, ssh, account := vaulttest.RemoteFixture(t)
	binding, err := v.RemoteMCP.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RememberRemoteMCP(ssh, "main", []mcpdirectory.Binding{binding}); err != nil {
		t.Fatal(err)
	}
	target := record.OwnTarget(v.Targets["production"])
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

func TestRemoteMCPVaultLimitRefusesAtomicallyAndClearsCandidate(t *testing.T) {
	v, _ := vaulttest.DirectoryFixture(t)
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

func TestProxyMetadataExportImportAndCleanup(t *testing.T) {
	v, server, first := vaulttest.ProxyFixture(t)
	const password = "synthetic proxy password"
	if err := v.SetServerProxy(server, &sshproxy.Config{Type: sshproxy.HTTP, Address: "proxy.invalid:8080", Username: "operator", Password: []byte(password)}); err != nil {
		t.Fatal(err)
	}
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	metadata, err := s.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(metadata)
	if err != nil || bytes.Contains(public, []byte(password)) || metadata.Servers[0].Proxy.Type != sshproxy.HTTP || !metadata.Servers[0].Proxy.Authenticated {
		t.Fatal("proxy metadata leaked authentication or lost routing")
	}
	plan, err := s.PrepareOwnerExport(ExportSelection{Servers: map[string][]string{server: {"main", "second"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	path := filepath.Join(t.TempDir(), "proxy-export.zip")
	if err := plan.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err != nil {
		t.Fatal(err)
	}
	opened, err := ownerarchive.ReadFile(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	imported, err := ParseOwnerImport(opened)
	if err != nil {
		t.Fatal(err)
	}
	defer imported.Close()
	preview, err := json.Marshal(imported.Preview())
	if err != nil || bytes.Contains(preview, []byte(password)) {
		t.Fatal("import preview exposed proxy authentication")
	}
	destination := importDestination(t, false, nil)
	if err := destination.ApplyOwnerImportDirectory(imported); err != nil {
		t.Fatal(err)
	}
	inspectSession(destination, func(got *Vault) {
		if !sshproxy.Equal(v.Targets[first].Proxy, got.Targets[first].Proxy) {
			t.Fatal("owner archive lost proxy settings or credentials")
		}
	})
	if err := destination.Apply(func(got *Vault) error {
		return got.SetServerProxy(server, &sshproxy.Config{Type: sshproxy.SOCKS5, Address: "changed.invalid:1080"})
	}); err != nil {
		t.Fatal(err)
	}
	if destination.VerifyOwnerImportDirectory(imported) != ErrImportChanged {
		t.Fatal("import recovery ignored a changed proxy route")
	}
	owned := v.Targets[first].Proxy.Password
	s.Discard()
	if !allZero(owned) {
		t.Fatal("database close retained proxy credentials")
	}
}
