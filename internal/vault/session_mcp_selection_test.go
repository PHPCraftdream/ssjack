package vault

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

func selectionSession(t *testing.T, save func(context.Context, []byte) error) (*Session, string, string, mcpdirectory.Binding, [32]byte) {
	t.Helper()
	state, server := directoryFixture(t)
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
	ctx := sessionTestContext(t)
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
	ctx := sessionTestContext(t)
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
		ctx := sessionTestContext(t)
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
