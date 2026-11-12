package ownerrotationtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func (r *rig) load() *vault.Vault {
	r.t.Helper()
	loaded, err := vault.Load(r.path, r.password)
	if err != nil {
		r.t.Fatal("synthetic encrypted rotation vault could not be reopened")
	}
	return loaded
}

// diskPhase is the durable journal phase, or "" without a journal.
func (r *rig) diskPhase() string {
	r.t.Helper()
	loaded := r.load()
	defer loaded.Close()
	if loaded.Rotation == nil {
		return ""
	}
	return loaded.Rotation.Phase
}

// activeKey copies the durable active private key of the synthetic account.
func (r *rig) activeKey() []byte {
	r.t.Helper()
	loaded := r.load()
	defer loaded.Close()
	profile, err := loaded.AccountProfile(r.serverID, "main")
	if err != nil {
		r.t.Fatal("synthetic selected account is missing")
	}
	return append([]byte(nil), loaded.Targets[profile].PrivateKey...)
}

// journalKey copies the replacement private key held by the encrypted journal.
func (r *rig) journalKey() []byte {
	r.t.Helper()
	loaded := r.load()
	defer loaded.Close()
	if loaded.Rotation == nil {
		r.t.Fatal("expected an encrypted rotation recovery journal")
	}
	return append([]byte(nil), loaded.Rotation.NewPrivate...)
}

// expectJournal asserts the durable phase and that the old key is still active.
func (r *rig) expectJournal(phase string) {
	r.t.Helper()
	active := r.activeKey()
	defer clear(active)
	if !bytes.Equal(active, r.oldPEM) || r.diskPhase() != phase {
		r.t.Fatal("durable active key or rotation journal phase differs from the expected state", phase)
	}
}

// retainCandidate returns the journal's distinct replacement key and registers
// it as a secret, so every capture is scanned for it before it is cleared.
func (r *rig) retainCandidate() []byte {
	r.t.Helper()
	candidate := r.journalKey()
	if len(candidate) == 0 || bytes.Equal(candidate, r.oldPEM) {
		r.t.Fatal("encrypted journal omitted its distinct replacement identity")
	}
	r.hide(candidate)
	return candidate
}

func rotationSnapshotReady(snapshot ownerdb.Snapshot) error {
	status := snapshot.Status.Database
	if snapshot.Status.Err != nil || snapshot.Status.Pending || snapshot.Status.Busy || status.Err != nil || status.Pending || status.SavedRevision != status.Revision || snapshot.CipherDigest == ([32]byte{}) {
		return errors.New("rotation requires an exact saved owner snapshot")
	}
	return nil
}

// attach authenticates a fresh owner helper to the running keeper; callers detach it.
func (r *rig) attach() *ownercontrol.Control {
	r.t.Helper()
	control, err := ownercontrol.Open(r.ctx, r.path, r.password)
	if err != nil {
		r.t.Fatal("independent owner could not authenticate to the running keeper")
	}
	return control
}

// scoped binds keeper operations to one exact snapshot revision.
func scoped(control *ownercontrol.Control, revision uint64) ownertui.Backend {
	return control.Backend().(interface {
		AtRevision(uint64) ownertui.Backend
	}).AtRevision(revision)
}

// retryDatabase performs the explicit local-save retry and returns the phase.
func (r *rig) retryDatabase() string {
	r.t.Helper()
	control := r.attach()
	defer control.Detach()
	before, err := control.RotationSnapshot(r.ctx)
	if err != nil {
		r.t.Fatal("owner snapshot was unavailable before explicit local-save retry")
	}
	retry := scoped(control, before.Status.Database.Revision)
	if retry.RetryDatabase() != nil || retry.Flush(r.ctx) != nil {
		r.t.Fatal("explicit local-save retry was refused or did not settle")
	}
	after, err := control.RotationSnapshot(r.ctx)
	if err != nil || rotationSnapshotReady(after) != nil || after.Rotation == nil {
		r.t.Fatal("explicit local-save retry did not produce a healthy saved snapshot")
	}
	return after.Rotation.Phase
}

// committed returns the durably selected replacement key and public key.
func (r *rig) committed(control *ownercontrol.Control) ([]byte, ssh.PublicKey) {
	r.t.Helper()
	loaded := r.load()
	complete := loaded.Rotation != nil && loaded.Rotation.Phase == vault.RotationComplete && loaded.Rotation.CommitDigest != ""
	loaded.Close()
	active := r.activeKey()
	signer, err := ssh.ParsePrivateKey(active)
	if !complete || err != nil || bytes.Equal(active, r.oldPEM) {
		clear(active)
		r.t.Fatal("durable active key is not a distinct replacement of a completed rotation")
	}
	saved, err := control.RotationSnapshot(r.ctx)
	if err != nil || rotationSnapshotReady(saved) != nil || saved.Rotation == nil || saved.Rotation.Phase != vault.RotationComplete {
		clear(active)
		r.t.Fatal("keeper did not report an exact durable completed rotation receipt")
	}
	r.hide(active)
	return active, signer.PublicKey()
}

// expectInventory asserts the vault directory holds only the named encrypted
// files and none of them contains registered private plaintext.
func (r *rig) expectInventory(allowed ...string) {
	r.t.Helper()
	entries, err := os.ReadDir(r.root)
	if err != nil {
		r.t.Fatal("synthetic vault inventory failed")
	}
	want := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		want[name] = true
	}
	for _, entry := range entries {
		if entry.IsDir() || !want[entry.Name()] {
			r.t.Fatalf("unexpected fixture artifact in synthetic vault directory: %s", entry.Name())
		}
		delete(want, entry.Name())
		r.expectEncrypted(filepath.Join(r.root, entry.Name()))
	}
	if len(want) != 0 {
		r.t.Fatal("expected synthetic encrypted vault artifact is missing")
	}
}

// expectEncrypted asserts a file holds none of the registered secrets or the fixed script.
func (r *rig) expectEncrypted(path string) {
	r.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		r.t.Fatal("synthetic fixture artifact could not be inspected")
	}
	defer clear(data)
	for _, secret := range append([][]byte{[]byte(rotationAuthorizedScript)}, r.secrets...) {
		if len(secret) > 0 && bytes.Contains(data, secret) {
			r.t.Fatal("synthetic fixture artifact contained private plaintext")
		}
	}
}

func (r *rig) fingerprintCount(fingerprint string) int {
	count := 0
	for _, value := range r.fixture.fingerprints() {
		if value == fingerprint {
			count++
		}
	}
	return count
}

// waitFingerprints waits until the fixture saw count handshakes of a key.
func (r *rig) waitFingerprints(fingerprint string, count int) {
	r.t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for r.fingerprintCount(fingerprint) < count {
		select {
		case <-r.ctx.Done():
			r.t.Fatal("fresh ordinary MCP SSH job did not authenticate with the selected new key")
		case <-ticker.C:
		}
	}
}

func publicFingerprint(t *testing.T, private []byte) string {
	t.Helper()
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil {
		t.Fatal("synthetic replacement key could not be parsed")
	}
	return ssh.FingerprintSHA256(signer.PublicKey())
}

// Fixture queries.

func (f *rotationSSHFixture) hasKey(key ssh.PublicKey) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.keys[string(key.Marshal())]
	return ok
}

// hasKeyFromPrivate accepts a raw ed25519 key or an encoded SSH private key.
func (f *rotationSSHFixture) hasKeyFromPrivate(private []byte) bool {
	var signer ssh.Signer
	var err error
	if len(private) == ed25519.PrivateKeySize {
		signer, err = ssh.NewSignerFromKey(ed25519.PrivateKey(private))
	} else {
		signer, err = ssh.ParsePrivateKey(private)
	}
	return err == nil && f.hasKey(signer.PublicKey())
}

func (f *rotationSSHFixture) mutationCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mutations
}
func (f *rotationSSHFixture) fingerprints() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.auths...)
}
func (f *rotationSSHFixture) waitHold(ctx context.Context) error {
	select {
	case <-f.holdStarted:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// serveHold keeps one admitted job open until released. A lost SSH transport is
// recorded: guarded stdout cannot prove liveness.
func (f *rotationSSHFixture) serveHold(ch ssh.Channel, finished <-chan struct{}) {
	_, _ = io.WriteString(ch, "SYNTHETIC-ROTATION-HELD\n")
	select {
	case f.holdStarted <- struct{}{}:
	default:
	}
	select {
	case <-f.holdRelease:
	case <-finished:
		f.holdLost.Store(true)
		return
	}
	exitStatus(ch, 0)
}
