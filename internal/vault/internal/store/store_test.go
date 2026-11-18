package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriterRoleExcludesForeignCommitButAllowsOwnedPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ktav")
	first, second := []byte("synthetic encrypted first"), []byte("synthetic encrypted second")
	if err := Commit(path, first, nil); err != nil {
		t.Fatal(err)
	}
	role, err := ClaimRole(path)
	if err != nil {
		t.Fatal(err)
	}
	defer role.Close()
	expected := sha256.Sum256(first)
	if err := Commit(path, second, &expected); !errors.Is(err, ErrWriterRole) {
		t.Fatal("foreign writer reached an occupied database")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatal("refused writer changed encrypted bytes")
	}
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatal("refused writer created a commit lock before admission")
	}
	if err := CommitWithRole(path, second, &expected, role); err != nil {
		t.Fatal(err)
	}
	if err := role.Close(); err != nil {
		t.Fatal(err)
	}
	expected = sha256.Sum256(second)
	if err := Commit(path, first, &expected); err != nil {
		t.Fatal("closed writer did not release exclusive publication")
	}
	if err := CommitWithRole(path, second, &expected, role); !errors.Is(err, ErrWriterRole) {
		t.Fatal("closed role authorized a later mutation")
	}
}

func TestWriterRoleRefusesAnotherDatabaseAndNeverRecreatesMissingFiles(t *testing.T) {
	first, second := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	for _, path := range []string{first, second} {
		if err := Commit(path, []byte("synthetic encrypted data"), nil); err != nil {
			t.Fatal(err)
		}
	}
	role, err := ClaimRole(first)
	if err != nil {
		t.Fatal(err)
	}
	defer role.Close()
	if err := CommitWithRole(second, []byte("changed"), nil, role); !errors.Is(err, ErrWriterRole) {
		t.Fatal("writer claim crossed database identity")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	expected := sha256.Sum256([]byte("synthetic encrypted data"))
	if err := Commit(missing, []byte("changed"), &expected); !errors.Is(err, ErrWriterRole) {
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
	if err := Commit(path, previous, nil); err != nil {
		t.Fatal(err)
	}
	role, err := ClaimRole(path)
	if err != nil {
		t.Fatal(err)
	}
	defer role.Close()
	for _, label := range []string{"before-restore", "before-upgrade"} {
		backup, err := ReplaceVerified(context.Background(), path, []byte("synthetic encrypted replacement"), previous, label)
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

func TestEncryptedFileCommitAndRevisionConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	first := []byte("opaque encrypted document one")
	second := []byte("opaque encrypted document two")
	if err := Commit(path, first, nil); err != nil {
		t.Fatal(err)
	}
	if err := Commit(path, second, nil); err == nil {
		t.Fatal("creation overwrote an existing vault")
	}
	revision := sha256.Sum256(first)
	if err := Commit(path, second, &revision); err != nil {
		t.Fatal(err)
	}
	if err := Commit(path, first, &revision); err == nil {
		t.Fatal("stale writer overwrote a newer vault")
	}
	data, err := ReadEncoded(path)
	if err != nil || !bytes.Equal(data, second) {
		t.Fatal("revision conflict changed stored bytes")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("lock or staging file was left after commit")
	}
}
