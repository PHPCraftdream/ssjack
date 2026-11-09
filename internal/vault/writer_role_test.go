package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriterRoleExcludesForeignCommitButAllowsOwnedPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ktav")
	first, second := []byte("synthetic encrypted first"), []byte("synthetic encrypted second")
	if err := commit(path, first, nil); err != nil {
		t.Fatal(err)
	}
	role, err := claimWriterRole(path)
	if err != nil {
		t.Fatal(err)
	}
	defer role.close()
	expected := sha256.Sum256(first)
	if err := commit(path, second, &expected); !errors.Is(err, ErrWriterRole) {
		t.Fatal("foreign writer reached an occupied database")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatal("refused writer changed encrypted bytes")
	}
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatal("refused writer created a commit lock before admission")
	}
	if err := commitWithRole(path, second, &expected, role); err != nil {
		t.Fatal(err)
	}
	if err := role.close(); err != nil {
		t.Fatal(err)
	}
	expected = sha256.Sum256(second)
	if err := commit(path, first, &expected); err != nil {
		t.Fatal("closed writer did not release exclusive publication")
	}
	if err := commitWithRole(path, second, &expected, role); !errors.Is(err, ErrWriterRole) {
		t.Fatal("closed role authorized a later mutation")
	}
}

func TestWriterRoleRefusesAnotherDatabaseAndNeverRecreatesMissingFiles(t *testing.T) {
	first, second := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	for _, path := range []string{first, second} {
		if err := commit(path, []byte("synthetic encrypted data"), nil); err != nil {
			t.Fatal(err)
		}
	}
	role, err := claimWriterRole(first)
	if err != nil {
		t.Fatal(err)
	}
	defer role.close()
	if err := commitWithRole(second, []byte("changed"), nil, role); !errors.Is(err, ErrWriterRole) {
		t.Fatal("writer claim crossed database identity")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	expected := sha256.Sum256([]byte("synthetic encrypted data"))
	if err := commit(missing, []byte("changed"), &expected); !errors.Is(err, ErrWriterRole) {
		t.Fatal("existing-database update created a missing database")
	}
	if _, err := os.Lstat(missing + ".lock"); !os.IsNotExist(err) {
		t.Fatal("refused missing database created commit state")
	}
}

func TestRestoreAndUpgradeRefuseBeforeCreatingRecoveryCopies(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "vault.ktav")
	previous := []byte("synthetic encrypted previous")
	if err := commit(path, previous, nil); err != nil {
		t.Fatal(err)
	}
	role, err := claimWriterRole(path)
	if err != nil {
		t.Fatal(err)
	}
	defer role.close()
	for _, label := range []string{"before-restore", "before-upgrade"} {
		backup, err := replaceVerified(context.Background(), path, []byte("synthetic encrypted replacement"), previous, label)
		if !errors.Is(err, ErrWriterRole) || backup != "" {
			t.Fatal("occupied replacement reached recovery-copy publication")
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 1 || entries[0].Name() != "vault.ktav" {
			t.Fatal("refused replacement created recovery or commit artifacts")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, previous) {
			t.Fatal("refused replacement changed the encrypted database")
		}
	}
}

func TestCancelledSessionCloseKeepsWriterUntilItsWorkerJoins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ktav")
	if err := commit(path, []byte("synthetic encrypted data"), nil); err != nil {
		t.Fatal(err)
	}
	role, err := claimWriterRole(path)
	if err != nil {
		t.Fatal(err)
	}
	entered, proceed := make(chan struct{}), make(chan struct{})
	s := newSession(NewDirectory(), func(ctx context.Context, _ []byte) error {
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
	if foreign, err := claimWriterRole(path); !errors.Is(err, ErrWriterRole) {
		if foreign != nil {
			foreign.close()
		}
		t.Fatal("cancelled close released a writer with active work")
	}
}

func TestFailedSessionSaveKeepsItsWriterRoleUntilExplicitDiscard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ktav")
	if err := commit(path, []byte("synthetic encrypted data"), nil); err != nil {
		t.Fatal(err)
	}
	role, err := claimWriterRole(path)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("synthetic persistence refusal")
	s := newSession(NewDirectory(), func(context.Context, []byte) error { return failure }, func() {})
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
	if foreign, err := claimWriterRole(path); !errors.Is(err, ErrWriterRole) {
		if foreign != nil {
			foreign.close()
		}
		t.Fatal("failed close released the live writer claim")
	}
	s.Discard()
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreign, err := claimWriterRole(path)
	if err != nil {
		t.Fatal("joined explicit discard retained the writer endpoint")
	}
	foreign.close()
}
