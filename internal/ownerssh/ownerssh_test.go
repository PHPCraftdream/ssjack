package ownerssh

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"golang.org/x/crypto/ssh"
)

const (
	fixtureProfile  = "fixture-profile"
	fixtureAddress  = "fixture.invalid:22"
	fixtureScope    = "fixture-scope"
	fixtureRevision = uint64(41)
)

var fixtureCiphertext = []byte("synthetic ciphertext bytes; not an authenticated vault")

type sourceFake struct {
	state       ownerdb.Snapshot
	snapshotErr error
	guard       *outputguard.Snapshot
	config      *ssh.ClientConfig
	address     string
	scope       string
	guardErr    error
	configErr   error
	onGuard     func()
	onConfig    func()
	snapshots   int
	guardCalls  int
	configCalls int
	gotRevision uint64
	gotDigest   [32]byte
	gotProfile  string
}

func (f *sourceFake) Snapshot() (ownerdb.Snapshot, error) {
	f.snapshots++
	return f.state, f.snapshotErr
}

func (f *sourceFake) OutputGuard(context.Context) (*outputguard.Snapshot, error) {
	f.guardCalls++
	if f.onGuard != nil {
		f.onGuard()
	}
	return f.guard, f.guardErr
}

func (f *sourceFake) AgentSSHAt(revision uint64, digest [32]byte, profile string) (*ssh.ClientConfig, string, string, error) {
	f.configCalls++
	f.gotRevision, f.gotDigest, f.gotProfile = revision, digest, profile
	if revision != f.state.Status.Database.Revision || digest != f.state.CipherDigest {
		return nil, "", "", errors.New("fixture epoch mismatch")
	}
	if f.onConfig != nil {
		f.onConfig()
	}
	if f.configErr != nil {
		return nil, "", "", f.configErr
	}
	return f.config, f.address, f.scope, nil
}

type materialFixture struct {
	path   string
	digest [32]byte
	guard  *outputguard.Snapshot
	config *ssh.ClientConfig
	source *sourceFake
}

func newMaterialFixture(t *testing.T) materialFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "synthetic-ciphertext")
	ciphertext := append([]byte(nil), fixtureCiphertext...)
	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(ciphertext)
	guard, err := outputguard.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	hostKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ClientConfig{
		User:            "fixture-user",
		Auth:            []ssh.AuthMethod{sshauth.Password([]byte("synthetic password"))},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}
	source := &sourceFake{
		state: ownerdb.Snapshot{
			Status:       ownerdb.Status{Database: vault.SessionStatus{Revision: fixtureRevision, SavedRevision: fixtureRevision}},
			CipherDigest: digest,
		},
		guard:   guard,
		config:  config,
		address: fixtureAddress,
		scope:   fixtureScope,
	}
	return materialFixture{path: path, digest: digest, guard: guard, config: config, source: source}
}

func TestOpenMaterialCapturesMatchingEpoch(t *testing.T) {
	fixture := newMaterialFixture(t)
	material, err := openMaterial(context.Background(), fixture.path, fixtureProfile, fixture.source)
	if err != nil {
		t.Fatalf("openMaterial() error = %v", err)
	}
	if material.Profile != fixtureProfile || material.Scope != fixtureScope || material.Revision != fixtureRevision ||
		material.Config != fixture.config || material.Address != fixtureAddress || material.Guard != fixture.guard {
		t.Fatalf("openMaterial() returned incoherent material: %+v", material)
	}
	if fixture.source.snapshots != 2 || fixture.source.guardCalls != 1 || fixture.source.configCalls != 1 {
		t.Fatalf("source calls = snapshots:%d guard:%d config:%d; want 2, 1, 1",
			fixture.source.snapshots, fixture.source.guardCalls, fixture.source.configCalls)
	}
	if fixture.source.gotRevision != fixtureRevision || fixture.source.gotDigest != fixture.digest || fixture.source.gotProfile != fixtureProfile {
		t.Fatalf("AgentSSHAt args = (%d, %x, %q), want (%d, %x, %q)",
			fixture.source.gotRevision, fixture.source.gotDigest, fixture.source.gotProfile,
			fixtureRevision, fixture.digest, fixtureProfile)
	}
}

func TestOpenMaterialRejectsUnhealthySnapshots(t *testing.T) {
	tests := []struct {
		name   string
		change func(*ownerdb.Snapshot)
	}{
		{name: "unsaved revision", change: func(s *ownerdb.Snapshot) { s.Status.Database.SavedRevision++ }},
		{name: "database pending", change: func(s *ownerdb.Snapshot) { s.Status.Database.Pending = true }},
		{name: "database failed", change: func(s *ownerdb.Snapshot) { s.Status.Database.Err = errors.New("synthetic save failure") }},
		{name: "owner busy", change: func(s *ownerdb.Snapshot) { s.Status.Busy = true }},
		{name: "owner pending", change: func(s *ownerdb.Snapshot) { s.Status.Pending = true }},
		{name: "owner failed", change: func(s *ownerdb.Snapshot) { s.Status.Err = errors.New("synthetic owner failure") }},
		{name: "missing cipher digest", change: func(s *ownerdb.Snapshot) { s.CipherDigest = [32]byte{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMaterialFixture(t)
			test.change(&fixture.source.state)
			if _, err := openMaterial(context.Background(), fixture.path, fixtureProfile, fixture.source); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("openMaterial() error = %v, want ErrUnavailable", err)
			}
			if fixture.source.guardCalls != 0 || fixture.source.configCalls != 0 {
				t.Fatalf("unhealthy source proceeded: guard calls %d, config calls %d", fixture.source.guardCalls, fixture.source.configCalls)
			}
		})
	}
}

func TestOpenMaterialRejectsSourceErrorsWithoutExposingDiagnostics(t *testing.T) {
	tests := []struct {
		name   string
		change func(*sourceFake)
	}{
		{name: "snapshot", change: func(f *sourceFake) { f.snapshotErr = errors.New("synthetic snapshot diagnostic") }},
		{name: "guard", change: func(f *sourceFake) { f.guardErr = errors.New("synthetic guard diagnostic") }},
		{name: "missing guard", change: func(f *sourceFake) { f.guard = nil }},
		{name: "configuration", change: func(f *sourceFake) { f.configErr = errors.New("synthetic configuration diagnostic") }},
		{name: "missing configuration", change: func(f *sourceFake) { f.config = nil }},
		{name: "missing address", change: func(f *sourceFake) { f.address = "" }},
		{name: "missing scope", change: func(f *sourceFake) { f.scope = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMaterialFixture(t)
			test.change(fixture.source)
			_, err := openMaterial(context.Background(), fixture.path, fixtureProfile, fixture.source)
			if err != ErrUnavailable {
				t.Fatalf("openMaterial() error = %v, want generic ErrUnavailable", err)
			}
		})
	}
}

func TestOpenMaterialRejectsDiskDigestMismatch(t *testing.T) {
	fixture := newMaterialFixture(t)
	if err := os.WriteFile(fixture.path, []byte("different synthetic ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openMaterial(context.Background(), fixture.path, fixtureProfile, fixture.source); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("openMaterial() error = %v, want ErrUnavailable", err)
	}
	if fixture.source.guardCalls != 0 || fixture.source.configCalls != 0 {
		t.Fatalf("digest mismatch proceeded: guard calls %d, config calls %d", fixture.source.guardCalls, fixture.source.configCalls)
	}
}

func TestOpenMaterialRejectsSnapshotDigestMismatch(t *testing.T) {
	fixture := newMaterialFixture(t)
	fixture.source.state.CipherDigest = sha256.Sum256([]byte("other synthetic ciphertext"))
	if _, err := openMaterial(context.Background(), fixture.path, fixtureProfile, fixture.source); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("openMaterial() error = %v, want ErrUnavailable", err)
	}
	if fixture.source.guardCalls != 0 || fixture.source.configCalls != 0 {
		t.Fatalf("snapshot digest mismatch proceeded: guard calls %d, config calls %d", fixture.source.guardCalls, fixture.source.configCalls)
	}
}

func TestOpenMaterialRejectsRevisionMutationAfterGuard(t *testing.T) {
	fixture := newMaterialFixture(t)
	fixture.source.onGuard = func() {
		fixture.source.state.Status.Database.Revision++
		fixture.source.state.Status.Database.SavedRevision++
	}
	if _, err := openMaterial(context.Background(), fixture.path, fixtureProfile, fixture.source); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("openMaterial() error = %v, want ErrUnavailable", err)
	}
	if fixture.source.configCalls != 1 || fixture.source.gotRevision != fixtureRevision || fixture.source.gotDigest != fixture.digest || fixture.source.gotProfile != fixtureProfile {
		t.Fatalf("AgentSSHAt call = count %d args (%d, %x, %q), want one call with original epoch/profile",
			fixture.source.configCalls, fixture.source.gotRevision, fixture.source.gotDigest, fixture.source.gotProfile)
	}
}

func TestOpenMaterialRejectsRevisionMutationBeforeFinalSnapshot(t *testing.T) {
	fixture := newMaterialFixture(t)
	fixture.source.onConfig = func() {
		fixture.source.state.Status.Database.Revision++
		fixture.source.state.Status.Database.SavedRevision++
	}
	if _, err := openMaterial(context.Background(), fixture.path, fixtureProfile, fixture.source); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("openMaterial() error = %v, want ErrUnavailable", err)
	}
	if fixture.source.snapshots != 2 || fixture.source.configCalls != 1 {
		t.Fatalf("source calls = snapshots:%d config:%d, want 2 and 1", fixture.source.snapshots, fixture.source.configCalls)
	}
}

func TestOpenMaterialRejectsFileReplacementBeforeFinalDigest(t *testing.T) {
	fixture := newMaterialFixture(t)
	fixture.source.onGuard = func() {
		replacement := fixture.path + ".replacement"
		if err := os.WriteFile(replacement, []byte("replacement synthetic ciphertext"), 0600); err != nil {
			t.Errorf("write replacement ciphertext: %v", err)
			return
		}
		if err := os.Remove(fixture.path); err != nil {
			t.Errorf("remove original ciphertext: %v", err)
			return
		}
		if err := os.Rename(replacement, fixture.path); err != nil {
			t.Errorf("replace synthetic ciphertext: %v", err)
		}
	}
	if _, err := openMaterial(context.Background(), fixture.path, fixtureProfile, fixture.source); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("openMaterial() error = %v, want ErrUnavailable", err)
	}
	if fixture.source.snapshots != 2 || fixture.source.configCalls != 1 {
		t.Fatalf("source calls = snapshots:%d config:%d, want 2 and 1", fixture.source.snapshots, fixture.source.configCalls)
	}
}

func TestDiskDigestBoundsAndIdentity(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "synthetic-ciphertext")
	data := []byte("bounded synthetic ciphertext")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := diskDigest(path)
	if err != nil || got != sha256.Sum256(data) {
		t.Fatalf("diskDigest() = (%x, %v), want SHA-256 of file", got, err)
	}
	if _, err := diskDigest(filepath.Join(directory, "missing")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("diskDigest(missing) error = %v, want ErrUnavailable", err)
	}
	if _, err := diskDigest(directory); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("diskDigest(directory) error = %v, want ErrUnavailable", err)
	}
	oversized := filepath.Join(directory, "oversized")
	if err := os.WriteFile(oversized, make([]byte, keyfile.MaxSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := diskDigest(oversized); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("diskDigest(oversized) error = %v, want ErrUnavailable", err)
	}
}
