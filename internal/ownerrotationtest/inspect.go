package ownerrotationtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	start := time.Now()
	loaded, err := vault.Load(r.path, r.password)
	class := rotationOperationOutcome(err, "loaded", "load-error")
	var evidence rotationEvidence
	if err == nil {
		evidence.diskPhase = "none"
		if loaded.Rotation != nil {
			evidence.diskPhase = safeRotationPhase(loaded.Rotation.Phase)
		}
	}
	r.diag.observe("disk-vault-load", class, start, evidence)
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
	if !bytes.Equal(active, r.oldPEM) {
		r.failCondition("durable-journal", "active-key-mismatch", "durable active key differs from the old key")
	}
	if r.diskPhase() != phase {
		r.failCondition("durable-journal", "wrong-phase", "durable rotation journal phase differs from the expected state")
	}
}

// retainCandidate returns the journal's distinct replacement key and registers
// it as a secret, so every capture is scanned for it before it is cleared.
func (r *rig) retainCandidate() []byte {
	r.t.Helper()
	candidate := r.journalKey()
	if len(candidate) == 0 {
		r.failCondition("journal-candidate", "missing-key", "encrypted journal omitted its replacement identity")
	}
	if bytes.Equal(candidate, r.oldPEM) {
		r.failCondition("journal-candidate", "old-key-reused", "encrypted journal omitted its distinct replacement identity")
	}
	r.hide(candidate)
	return candidate
}

func observedRotationPhase(rotation *vault.RotationInfo) rotationPhase {
	if rotation == nil {
		return "none"
	}
	return safeRotationPhase(rotation.Phase)
}

func snapshotStats(snapshot ownerdb.Snapshot) rotationSnapshotStats {
	status := snapshot.Status.Database
	return rotationSnapshotStats{
		phase: observedRotationPhase(snapshot.Rotation), revision: status.Revision, savedRevision: status.SavedRevision,
		ownerError: snapshot.Status.Err != nil, ownerPending: snapshot.Status.Pending, ownerBusy: snapshot.Status.Busy,
		databaseError: status.Err != nil, databasePending: status.Pending, digest: snapshot.CipherDigest != ([32]byte{}),
	}
}

func rotationSnapshotState(snapshot ownerdb.Snapshot, err error, ready, complete bool) string {
	if err != nil {
		return rotationOperationOutcome(err, "", "snapshot-error")
	}
	if ready {
		status := snapshot.Status.Database
		switch {
		case snapshot.Status.Err != nil:
			return "owner-status-error"
		case snapshot.Status.Pending:
			return "owner-pending"
		case snapshot.Status.Busy:
			return "owner-busy"
		case status.Err != nil:
			return "database-status-error"
		case status.Pending:
			return "database-pending"
		case status.SavedRevision != status.Revision:
			return "unsaved-revision"
		case snapshot.CipherDigest == ([32]byte{}):
			return "missing-cipher-digest"
		}
	}
	if snapshot.Rotation == nil {
		return "missing-receipt"
	}
	if complete && snapshot.Rotation.Phase != vault.RotationComplete {
		return "wrong-phase"
	}
	return "matched"
}

func (r *rig) recordSnapshot(name, class string, start time.Time, snapshot ownerdb.Snapshot, err error) {
	var evidence rotationEvidence
	if err == nil {
		evidence.snapshot = snapshotStats(snapshot)
	}
	r.diag.observe(name, class, start, evidence)
}

// attach authenticates a fresh owner helper to the running keeper; callers detach it.
func (r *rig) attach() *ownercontrol.Control {
	r.t.Helper()
	start := time.Now()
	control, err := ownercontrol.Open(r.ctx, r.path, r.password)
	r.diag.observe("owner-attach", rotationOperationOutcome(err, "attached", "attach-error"), start, rotationEvidence{})
	if err != nil {
		r.t.Fatal("independent owner could not authenticate to the running keeper")
	}
	return control
}

// scoped selects the revision for operations that use the backend's revision binding.
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
	start := time.Now()
	before, err := control.RotationSnapshot(r.ctx)
	r.recordSnapshot("retry-before-snapshot", rotationOperationOutcome(err, "read", "snapshot-error"), start, before, err)
	if err != nil {
		r.t.Fatal("owner snapshot was unavailable before explicit local-save retry")
	}
	retry := scoped(control, before.Status.Database.Revision)
	start = time.Now()
	err = retry.RetryDatabase()
	r.diag.observe("retry-database-request", rotationOperationOutcome(err, "accepted", "retry-error"), start, rotationEvidence{})
	if err != nil {
		r.t.Fatal("explicit local-save retry request failed")
	}
	start = time.Now()
	err = retry.Flush(r.ctx)
	r.diag.observe("retry-database-flush", rotationOperationOutcome(err, "returned-ok", "flush-error"), start, rotationEvidence{})
	if err != nil {
		r.t.Fatal("explicit local-save retry flush failed")
	}
	start = time.Now()
	after, err := control.RotationSnapshot(r.ctx)
	class := rotationSnapshotState(after, err, true, false)
	r.recordSnapshot("retry-after-snapshot", class, start, after, err)
	if class != "matched" {
		r.t.Fatal("explicit local-save retry did not produce a healthy saved snapshot:", class)
	}
	return after.Rotation.Phase
}

// committed returns the durably selected replacement key and public key.
func (r *rig) committed(control *ownercontrol.Control) ([]byte, ssh.PublicKey) {
	r.t.Helper()
	loaded := r.load()
	class := "matched"
	switch {
	case loaded.Rotation == nil:
		class = "missing-receipt"
	case loaded.Rotation.Phase != vault.RotationComplete:
		class = "wrong-phase"
	case loaded.Rotation.CommitDigest == "":
		class = "missing-commit-digest"
	}
	loaded.Close()
	active := r.activeKey()
	signer, err := ssh.ParsePrivateKey(active)
	if class == "matched" {
		switch {
		case err != nil:
			class = "active-key-parse-error"
		case bytes.Equal(active, r.oldPEM):
			class = "old-key-reused"
		}
	}
	if class != "matched" {
		clear(active)
		r.failCondition("committed-disk-state", class, "durable active key is not a distinct replacement of a completed rotation")
	}
	start := time.Now()
	saved, err := control.RotationSnapshot(r.ctx)
	class = rotationSnapshotState(saved, err, true, true)
	r.recordSnapshot("committed-snapshot", class, start, saved, err)
	if class != "matched" {
		clear(active)
		r.t.Fatal("keeper did not report an exact durable completed rotation receipt:", class)
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
		if entry.IsDir() {
			r.t.Fatalf("unexpected fixture artifact: class=directory name-length=%d", len(entry.Name()))
		}
		if !want[entry.Name()] {
			r.t.Fatalf("unexpected fixture artifact: class=unexpected-entry name-length=%d", len(entry.Name()))
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
	for _, secret := range append([][]byte{[]byte(rotationAuthorizedScript), []byte(rotationRetireScript)}, r.secrets...) {
		if len(secret) > 0 && bytes.Contains(data, secret) {
			r.t.Fatal("synthetic fixture artifact contained private plaintext")
		}
	}
}

func (r *rig) fingerprintCount(fingerprint string) int {
	r.fixture.mu.Lock()
	defer r.fixture.mu.Unlock()
	count := 0
	for _, value := range r.fixture.auths {
		if value == fingerprint {
			count++
		}
	}
	return count
}

// waitFingerprints waits until the fixture saw count handshakes of a key.
func (r *rig) waitFingerprints(fingerprint string, count int) {
	r.t.Helper()
	start := time.Now()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		observed := r.fingerprintCount(fingerprint)
		if observed >= count {
			r.recordHandshakes("fingerprint-wait", "matched", start, observed, count)
			return
		}
		select {
		case <-r.ctx.Done():
			r.recordHandshakes("fingerprint-wait", rotationContextOutcome(r.ctx.Err()), start, observed, count)
			r.t.Fatal("fresh ordinary MCP SSH job did not authenticate with the selected new key")
		case <-ticker.C:
		}
	}
}

func (r *rig) recordHandshakes(name, class string, start time.Time, observed, expected int) {
	r.diag.observe(name, class, start, rotationEvidence{handshakes: rotationCounts{known: true, observed: observed, expected: expected}})
}

func (r *rig) expectHandshake(name string, observed int, message string) {
	r.t.Helper()
	class := "matched"
	if observed == 0 {
		class = "missing-handshake"
	}
	r.recordHandshakes(name, class, time.Time{}, observed, 1)
	if observed == 0 {
		r.t.Fatal(message)
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
